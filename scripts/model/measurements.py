"""Core probe records as this repository stores them.

A run of core_probe.py produces one full record, stored as one line:

  measurements/<emulator>.jsonl    one record per line, append-only

A line holds the whole run: claim, method, observable, result, host, inputs
by hash, core build and frontend commit, and every repetition of every
variant in full (per-frame hashes, core logs, declared options), with the
raw timing values the statistics were computed from.

A record id is the date and the first 12 hex digits of the sha256 of the
record without its id, in canonical JSON. A record carried over from the
first layout keeps the id it had, which hashes that full record.

Standard library only: core_probe.py, validate_schemas.py and the site
read it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

RECORD_VERSION = 5
# 3: before the boot oracle. 4: every repetition and variant carries a verdict.
# 5: and the BIOS the core ran.
RECORD_VERSIONS = (3, 4, 5)
RECORDS_DIR = "measurements"
ID_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}-[0-9a-f]{12}$")
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")


class RecordError(ValueError):
    """A record line that cannot be read."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def value_sha1(value: object) -> str:
    """The sha1 of a value in canonical JSON."""
    return hashlib.sha1(canonical(value)).hexdigest()


def slugify(text: str, limit: int = 40) -> str:
    """Lowercase words joined by hyphens, cut at a word boundary."""
    words = re.findall(r"[a-z0-9]+", text.lower())
    out = ""
    for word in words:
        candidate = f"{out}-{word}" if out else word
        if len(candidate) > limit:
            break
        out = candidate
    return out or "record"


def record_id(record: dict) -> str:
    body = {key: value for key, value in record.items() if key != "id"}
    return f"{record['recorded_at'][:10]}-{sha256_hex(canonical(body))[:12]}"


def seal(record: dict) -> dict:
    """The record with its id."""
    return {**record, "id": record_id(record)}


def line_text(record: dict) -> str:
    """The record as one line of its .jsonl file, keys in a fixed order."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def records_path(emulator: str) -> str:
    return f"{RECORDS_DIR}/{emulator}.jsonl"


# The campaign's own files beside the records: append-only like them, one
# line per finding, per pass or per pack probe, each line hashed to its id.
# No profile takes these names (tests/test_campaign.py checks it).
FINDINGS = "findings"
CAMPAIGN_RUNS = "campaign-runs"
PACK_PROBES = "pack-probes"
# The subject of every core_probe record a pack probe writes.
PACK_SUBJECT_PREFIX = "pack-"
CAMPAIGN_FILES = {
    FINDINGS: ("found_at", "campaign-finding.schema.json"),
    CAMPAIGN_RUNS: ("started_at", "campaign-run.schema.json"),
    PACK_PROBES: ("probed_at", "pack-probe.schema.json"),
}


def line_id(line: dict, date_key: str) -> str:
    body = {key: value for key, value in line.items() if key != "id"}
    return f"{line[date_key][:10]}-{sha256_hex(canonical(body))[:12]}"


def seal_line(line: dict, date_key: str) -> dict:
    return {**line, "id": line_id(line, date_key)}


def read_campaign(root: Path, name: str) -> list[dict]:
    """The lines of one campaign file, each checked against its id."""
    path = root / records_path(name)
    if not path.is_file():
        return []
    date_key = CAMPAIGN_FILES[name][0]
    lines = parse_lines(path.read_text(encoding="utf-8"), records_path(name))
    problems = []
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        rid = str(line.get("id", ""))
        if not ID_PATTERN.match(rid) or date_key not in line or line_id(line, date_key) != rid:
            problems.append(f"{records_path(name)}:{number}: id {rid!r} does not hash the line")
        if rid in seen:
            problems.append(f"{records_path(name)}:{number}: id {rid} appears twice")
        seen.add(rid)
    if problems:
        raise MeasurementsError("\n  ".join(problems))
    return lines


IDENTITY = ("id", "emulator", "subject", "supersedes", "migrated_from_version")


def first_layout(record: dict) -> dict:
    """A record as the first layout wrote it: no id, emulator, subject or
    supersedes, record_version 1."""
    old = {key: value for key, value in record.items() if key not in IDENTITY}
    old["record_version"] = 1
    return old


def check_line(record: dict) -> list[str]:
    """The structural rules a line holds, without a JSON Schema validator."""
    rid = record.get("id", "")
    problems = []
    if record.get("record_version") not in RECORD_VERSIONS:
        problems.append(f"{rid}: record_version {record.get('record_version')} not in {RECORD_VERSIONS}")
    if not ID_PATTERN.match(str(rid)):
        problems.append(f"{rid!r}: not an id of the form YYYY-MM-DD-<12 hex>")
    elif str(record.get("recorded_at", ""))[:10] != rid[:10]:
        problems.append(f"{rid}: id date differs from recorded_at {record.get('recorded_at')}")
    elif record.get("migrated_from_version") == 1:
        digest = sha256_hex(canonical(first_layout(record)))[:12]
        if not rid.endswith(f"-{digest}"):
            problems.append(f"{rid}: id does not hash the first-layout record ({digest})")
    elif record_id(record) != rid:
        problems.append(f"{rid}: id does not hash the record ({record_id(record)})")
    problems.extend(f"{rid}: {key} {record.get(key)!r} is not a lowercase slug"
                    for key in ("emulator", "subject") if not SLUG_PATTERN.match(str(record.get(key, ""))))
    return problems


def parse_lines(text: str, label: str) -> list[dict]:
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise RecordError(f"{label}:{number}: empty line")
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RecordError(f"{label}:{number}: {exc}") from exc
    return out


def appended_only(before: str, after: str) -> str | None:
    """None when ``after`` keeps every line of ``before``, in place, and
    only adds lines at its end, otherwise the first line that moved."""
    old, new = before.splitlines(), after.splitlines()
    for number, line in enumerate(old, 1):
        if number > len(new):
            return f"line {number} removed"
        if new[number - 1] != line:
            return f"line {number} changed"
    return None


def live(records: Iterable[dict]) -> list[dict]:
    """The records no later record supersedes."""
    records = list(records)
    superseded = {r["supersedes"] for r in records if r.get("supersedes")}
    return [r for r in records if r["id"] not in superseded]


class MeasurementsError(RuntimeError):
    """The records of a tree cannot be read, or break a rule."""


@dataclass(frozen=True)
class Stored:
    """One record line as read from the tree."""

    emulator: str
    line: int
    record: dict


def tree_files(root: Path) -> dict[str, Path]:
    """Repository path -> file of everything under ``root``/measurements."""
    base = root / RECORDS_DIR
    if not base.is_dir():
        return {}
    return {path.relative_to(root).as_posix(): path
            for path in sorted(base.rglob("*")) if path.is_file()}


def read_records(root: Path) -> list[Stored]:
    """Every record line under ``root``, each checked against its rules."""
    files = tree_files(root)
    problems: list[str] = []
    stored: list[Stored] = []
    for path in sorted(files):
        emulator = path[len(RECORDS_DIR) + 1:].removesuffix(".jsonl")
        if not path.endswith(".jsonl") or "/" in emulator:
            problems.append(f"{path}: {RECORDS_DIR}/ holds <emulator>.jsonl files only")
            continue
        if emulator in CAMPAIGN_FILES:
            continue
        seen: set[str | None] = set()
        try:
            records = parse_lines(files[path].read_text(encoding="utf-8"), path)
        except RecordError as exc:
            problems.append(str(exc))
            continue
        for number, record in enumerate(records, 1):
            where = f"{path}:{number}"
            problems.extend(f"{where}: {p}" for p in check_line(record))
            if record.get("emulator") != emulator:
                problems.append(f"{where}: emulator {record.get('emulator')!r} in {path}")
            if record.get("id") in seen:
                problems.append(f"{where}: id {record.get('id')} appears twice")
            if record.get("supersedes") and record["supersedes"] not in seen:
                problems.append(f"{where}: supersedes {record['supersedes']}, no earlier line of this file")
            seen.add(record.get("id"))
            stored.append(Stored(emulator, number, record))
    if problems:
        raise MeasurementsError("records under {}:\n  {}".format(root, "\n  ".join(problems)))
    return stored


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)


def committed_files(root: Path, ref: str) -> dict[str, bytes]:
    """Path -> content of every file under measurements/ at ``ref``."""
    listing = _git(root, "ls-tree", "-r", "-z", "--name-only", ref, "--", RECORDS_DIR)
    if listing.returncode != 0:
        raise MeasurementsError(f"git ls-tree {ref}: {listing.stderr.decode(errors='replace').strip()}")
    out = {}
    for path in filter(None, listing.stdout.decode("utf-8").split("\0")):
        blob = _git(root, "show", f"{ref}:{path}")
        if blob.returncode != 0:
            raise MeasurementsError(f"git show {ref}:{path}: {blob.stderr.decode(errors='replace').strip()}")
        out[path] = blob.stdout
    return out


def append_only_problems(root: Path, ref: str = "HEAD") -> list[str]:
    """What the tree under ``root`` changed or removed of the lines ``ref``
    holds. Lines added at the end and new files are allowed."""
    before, after = committed_files(root, ref), tree_files(root)
    problems = []
    for path, content in sorted(before.items()):
        if path not in after:
            problems.append(f"{path}: removed")
            continue
        now = after[path].read_bytes()
        if now == content:
            continue
        if path.endswith(".jsonl"):
            moved = appended_only(content.decode("utf-8"), now.decode("utf-8"))
            if moved:
                problems.append(f"{path}: {moved}")
        else:
            problems.append(f"{path}: rewritten")
    return problems


def last_commit(root: Path) -> str | None:
    """The last commit that touched the records: the one their permalinks name."""
    proc = _git(root, "log", "-1", "--format=%H", "--", RECORDS_DIR)
    commit = proc.stdout.decode().strip() if proc.returncode == 0 else ""
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None
