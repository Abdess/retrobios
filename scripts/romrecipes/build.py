"""Build: an archive rebuilt from the members the collection holds, verified before it lands."""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from core.hashing import compute_hashes
from core.torrentzip import write_torrentzip, zlib_ng_version
from core.ziptools import is_archive_path, zip_members
from romrecipes.collection import on_disk
from romrecipes.members import member_sha1, member_opener


# --- build ------------------------------------------------------------------


@dataclass
class Source:
    path: Path
    member: str | None  # None for a loose file


@dataclass
class AtomIndex:
    """Where each member sha1 can be read in the collection."""

    loose: dict[str, Path] = field(default_factory=dict)
    inside: dict[str, list[tuple[Path, str]]] = field(default_factory=dict)

    @classmethod
    def from_collection(cls, ledger: dict[str, dict], db: dict, root: Path) -> AtomIndex:
        index = cls()
        for entry in (db.get("files") or {}).values():
            path = on_disk(root, entry.get("path", ""))
            if not is_archive_path(entry.get("path", "")) and path.is_file():
                index.loose.setdefault(entry["sha1"], path)
        for archive, record in sorted(ledger.items()):
            path = on_disk(root, archive)
            if not path.is_file():
                continue
            for member in record.get("members", []):
                index.inside.setdefault(member["sha1"], []).append((path, member["name"]))
        return index

    def find(self, sha1: str, own: Path) -> Source | None:
        """A loose copy first, then another archive, then the archive itself."""
        if sha1 in self.loose:
            return Source(self.loose[sha1], None)
        holders = self.inside.get(sha1, [])
        for path, member in holders:
            if path != own:
                return Source(path, member)
        for path, member in holders:
            return Source(path, member)
        return None

    def held(self, sha1: str) -> bool:
        return sha1 in self.loose or sha1 in self.inside


@dataclass
class BuildResult:
    path: str
    status: str  # exact, canonical, impossible, failed
    output: str = ""
    detail: str = ""
    missing: list[dict] = field(default_factory=list)
    own_members: int = 0


def _members_match(built: Path, members: list[dict]) -> str:
    """Empty when *built* holds exactly *members*, else what differs."""
    expected = sorted((m["name"], m["size"], m["crc32"], m["sha1"]) for m in members)
    held = sorted(
        (member.name, member.size, member.crc32, member_sha1(built, member.name))
        for member in zip_members(built)
    )
    if held == expected:
        return ""
    missing = sorted(set(expected) - set(held))
    extra = sorted(set(held) - set(expected))
    return f"members differ: expected {missing[:3]}, built {extra[:3]}"


def destination(record_path: str, output_dir: Path) -> Path:
    """Where a build lands: the archive's path below ``bios/``, under *output_dir*."""
    parts = Path(record_path).parts
    relative = Path(*parts[1:]) if parts and parts[0] == "bios" else Path(record_path)
    return output_dir / relative


def build_archive(
    record: dict,
    atoms: AtomIndex,
    output_dir: Path,
    root: Path,
    attempts: int = 2,
) -> BuildResult:
    """Build *record* from held members into *output_dir*, verified.

    The bytes are written to a scratch file beside the destination and read
    back from disk: an exact recipe must give its recorded sha1, a canonical
    one its members. A mismatch is built once more, then refused: nothing
    wrong is ever moved to the destination. Under zlib-ng an exact recipe is
    checked by its members only and never reported exact.
    """
    path = record["path"]
    own = on_disk(root, path)
    sources: list[tuple[str, Source]] = []
    missing: list[dict] = []
    for member in record["members"]:
        source = atoms.find(member["sha1"], own)
        if source is None:
            missing.append(member)
        else:
            sources.append((member["name"], source))
    if missing:
        return BuildResult(path, "impossible", missing=missing)
    own_members = sum(1 for _name, source in sources if source.path == own)
    ng = zlib_ng_version()
    exact = record["rebuild"] == "exact" and not ng
    target = destination(path, output_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    scratch = target.with_name(f".{target.name}.{os.getpid()}.part")
    detail = ""
    try:
        for _attempt in range(attempts):
            with scratch.open("wb") as handle:
                write_torrentzip(
                    handle,
                    [(name, member_opener(source.path, source.member)) for name, source in sources],
                )
            if exact:
                written = compute_hashes(scratch, frozenset({"sha1"}), cache=False)["sha1"]
                detail = "" if written == record["sha1"] else (
                    f"sha1 {written} is not the recorded {record['sha1']}"
                )
            else:
                detail = _members_match(scratch, record["members"])
            if not detail:
                os.replace(scratch, target)
                status = "exact" if exact else "canonical"
                note = (
                    f"zlib-ng {ng}: exact bytes not claimed, members verified"
                    if ng and record["rebuild"] == "exact" else ""
                )
                return BuildResult(path, status, str(target), note, own_members=own_members)
    finally:
        if scratch.exists():
            scratch.unlink()
    return BuildResult(path, "failed", detail=detail, own_members=own_members)


def select(ledger: dict[str, dict], wanted: str, root: Path) -> list[dict]:
    """Records named by a path (relative or absolute) or by a file name."""
    candidate = Path(wanted)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError:
            return []
    key = candidate.as_posix()
    if key in ledger:
        return [ledger[key]]
    return [record for path, record in sorted(ledger.items()) if Path(path).name == wanted]


def build_targets(ledger: dict[str, dict], wanted: str | None, root: Path) -> list[dict]:
    """Every record in path order when *wanted* is None, else those it names under *root*."""
    if wanted is None:
        return [ledger[path] for path in sorted(ledger)]
    return select(ledger, wanted, root)


def build_records(
    records: list[dict],
    atoms: AtomIndex,
    output_dir: Path,
    root: Path,
    discard: bool = False,
) -> Iterator[BuildResult]:
    """Build each record in turn. With *discard* a verified build is deleted once seen."""
    for record in records:
        result = build_archive(record, atoms, output_dir, root)
        yield result
        if discard and result.status in ("exact", "canonical"):
            Path(result.output).unlink()


@dataclass
class BuildTally:
    """A build run counted by status, with the archives that read their own members."""

    counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    own: list[tuple[str, int]] = field(default_factory=list)

    def add(self, result: BuildResult) -> None:
        self.counts[result.status] += 1
        if result.own_members:
            self.own.append((result.path, result.own_members))

    @property
    def own_members(self) -> int:
        return sum(n for _p, n in self.own)
