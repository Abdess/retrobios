"""Profiles that declare no files, read for a source that asks for a directory."""
from __future__ import annotations

import os
from pathlib import Path

from core import upstream
from model.sourceref import ref_role, split_source_ref
from model.sources import source_yaml_file
from profiling.citations import collect_citations
from profiling.repos import select_views

# Ways a program asks for somewhere to read from.
SIGNALS = (
    "RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY",
    "GET_SYSTEM_DIRECTORY",
    "system_directory",
    "get_system_directory",
)

SOURCE_SUFFIX = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".m", ".mm")


def cited_paths(document: dict) -> list[str]:
    """Source paths the profile points at, in document order, deduplicated."""
    seen: list[str] = []
    for citation in collect_citations(document):
        for part in split_source_ref(citation.ref):
            path = ref_role(part.path)[1]
            if path.endswith(SOURCE_SUFFIX) and path not in seen:
                seen.append(path)
    return seen


def audit(
    name: str, emulators_dir: str, cache_dir: str, offline: bool
) -> list[tuple[str, str]] | None:
    """Signals found in the sources a fileless profile cites."""
    document = source_yaml_file(os.path.join(emulators_dir, f"{name}.yml")) or {}
    if settled_before_reading(document):
        return None
    views = select_views(document, cache_dir, offline)
    if not views:
        return []
    hits: list[tuple[str, str]] = []
    for path in cited_paths(document)[:40]:
        for view in views:
            lines = upstream.fetch_file(view.repo, view.pin, path, cache_dir, offline)
            if lines is None:
                continue
            for signal in SIGNALS:
                if any(signal in line for line in lines):
                    hits.append((path, signal))
                    break
            break
    return hits


def settled_before_reading(document: dict) -> bool:
    """A profile answered without reading its sources."""
    return bool(
        document.get("files")
        # The same binary under another name: its files are its target's.
        or document.get("type") == "alias"
        # Someone read this one and wrote down why nothing is declared. The
        # check exists to find the profiles nobody has answered yet, and an
        # answer that goes stale shows up as a drifting ref instead.
        or str(document.get("exclusion_note") or "").strip()
        # The load is declared, as a directory rather than a file. dinothawr
        # reads system_dir/dinothawr/ and says so there. That is coverage, not
        # an assertion waiting to age.
        or document.get("data_directories")
    )


def unanswered_profiles(emulators_dir: str) -> list[str]:
    """Every profile under emulators_dir that is not settled before reading."""
    known = sorted(path.stem for path in Path(emulators_dir).glob("*.yml"))
    return [
        name for name in known
        if not settled_before_reading(source_yaml_file(Path(emulators_dir) / f"{name}.yml") or {})
    ]
