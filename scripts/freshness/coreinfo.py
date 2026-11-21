"""libretro-core-info against the profiles and the .info blobs recorded as reviewed."""

from __future__ import annotations

import json
from pathlib import Path

from core import upstream
from core.artifacts import write_text_atomic
from core.cli import InputMissing, suggest_names
from core.paths import REPO_ROOT
from freshness.findings import OK, SKIPPED, STALE, UNKNOWN, Finding
from freshness.targets import profile_name_index


CORE_INFO_REPO = "https://github.com/libretro/libretro-core-info"
# The git blob of every .info as last reviewed: `--record-coreinfo` writes it.
CORE_INFO_RECORD = REPO_ROOT / "platforms" / "_core_info.json"


def core_info_blobs(cache_dir: str, offline: bool) -> dict[str, str] | None:
    """Every core the libretro core-info repository describes, with the git
    blob of its .info."""
    repo = upstream.parse_repo(CORE_INFO_REPO)
    if repo is None:
        return None
    payload = upstream.cached_api(
        f"{repo.api_base}/repos/{repo.slug}/contents?per_page=100",
        cache_dir,
        offline,
        upstream.MOVING_TTL,
    )
    if not isinstance(payload, list):
        return None
    blobs = {}
    for entry in payload:
        name = entry.get("name", "") if isinstance(entry, dict) else ""
        if name.endswith("_libretro.info"):
            blobs[name[: -len("_libretro.info")]] = str(entry.get("sha") or "")
    return dict(sorted(blobs.items()))


def core_info_names(cache_dir: str, offline: bool) -> list[str] | None:
    """Every core the libretro core-info repository describes."""
    blobs = core_info_blobs(cache_dir, offline)
    return None if blobs is None else list(blobs)


def load_core_info_record(path: Path = CORE_INFO_RECORD) -> dict[str, str] | None:
    if not path.is_file():
        return None
    return dict((json.loads(path.read_text(encoding="utf-8")) or {}).get("blobs") or {})


def record_core_info(
    blobs: dict[str, str], names: list[str], path: Path = CORE_INFO_RECORD
) -> list[str]:
    """Record the current blob of *names* (every .info when empty) as reviewed.

    Naming the cores keeps a change nobody read out of the record.
    """
    unknown = sorted(set(names) - set(blobs))
    if unknown:
        raise InputMissing(
            f"no such .info in core-info: {', '.join(unknown)}. "
            + suggest_names(unknown, list(blobs), "libretro-core-info")
        )
    recorded = load_core_info_record(path) or {}
    recorded.update({n: blobs[n] for n in (names or blobs)})
    payload = {"repository": CORE_INFO_REPO, "blobs": dict(sorted(recorded.items()))}
    write_text_atomic(str(path), json.dumps(payload, indent=2) + "\n")
    return sorted(names or blobs)


def coreinfo_drift(
    blobs: dict[str, str], recorded: dict[str, str], profiles: dict[str, dict]
) -> list[str]:
    """Profiled cores whose .info is not the one recorded as reviewed.

    The .info is no authority, but a new firmwareN_path in it is the
    cheapest sign that a profile needs reading again.
    """
    index = {key.casefold() for key in profile_name_index(profiles)}
    return [n for n, sha in blobs.items()
            if n.casefold() in index and recorded.get(n) != sha]


def coreinfo_gaps(
    names: list[str], profiles: dict[str, dict]
) -> tuple[list[str], list[tuple[str, str]]]:
    """Cores core-info knows that the profiles do not, and profiles that
    call standalone a core libretro now builds.

    Matching folds case: the buildbot serves lower-case names while a few
    .info files keep the project's own casing.
    """
    index: dict[str, set[str]] = {}
    for key, claimants in profile_name_index(profiles).items():
        index.setdefault(key.casefold(), set()).update(claimants)
    unprofiled = [n for n in names if n.casefold() not in index]
    # A name only standalone profiles claim: libretro now builds a core
    # nothing in the collection describes as one.
    standalone = [
        (n, sorted(index[n.casefold()])[0])
        for n in names
        if n.casefold() in index
        and all(
            str(profiles[c].get("type", "")).strip() == "standalone"
            for c in index[n.casefold()]
        )
    ]
    return unprofiled, standalone


def check_coreinfo(
    profiles: dict[str, dict], cache_dir: str, offline: bool,
    record_path: Path = CORE_INFO_RECORD,
) -> list[Finding]:
    blobs = core_info_blobs(cache_dir, offline)
    if blobs is None and offline:
        # Offline with no cached listing, nothing was asked of the upstream.
        return [Finding("coreinfo", "libretro-core-info", SKIPPED, detail="offline")]
    if blobs is None:
        return [Finding("coreinfo", "libretro-core-info", UNKNOWN, detail="listing unavailable")]
    names = list(blobs)
    unprofiled, standalone = coreinfo_gaps(names, profiles)
    findings = [
        Finding(
            "coreinfo",
            "libretro-core-info",
            STALE if unprofiled or standalone else OK,
            local=f"{len(names) - len(unprofiled)} profiled",
            remote=f"{len(names)} .info files",
        )
    ]
    findings.extend(
        Finding("coreinfo", name, STALE, detail="no profile claims this core name")
        for name in unprofiled
    )
    findings.extend(
        Finding(
            "coreinfo",
            name,
            STALE,
            local=f"{key}: type standalone",
            detail="core-info describes a libretro build of it",
        )
        for name, key in standalone
    )
    recorded = load_core_info_record(record_path)
    if recorded is None:
        findings.append(Finding(
            "coreinfo", "reviewed .info", UNKNOWN,
            detail=f"no {record_path.name}: run python scripts/check_freshness.py --record-coreinfo",
        ))
        return findings
    findings.extend(
        Finding(
            "coreinfo", name, STALE,
            local=(recorded.get(name) or "not recorded")[:12], remote=blobs[name][:12],
            detail=(".info changed since reviewed: read its firmware, then "
                    f"python scripts/check_freshness.py --record-coreinfo {name}"),
        )
        for name in coreinfo_drift(blobs, recorded, profiles)
    )
    return findings
