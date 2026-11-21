"""The file entries the registered platforms and the emulator profiles declare, and their hash fields."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.cli import SourceUnreadable
from model.profiles import source_yaml_paths
from model.registry import list_registered_platforms
from model.sources import source_yaml_file


def hash_values(value: object) -> list[str]:
    """A hash field as lowercase values, whether written alone or as a list."""
    if not value:
        return []
    values = value if isinstance(value, list) else str(value).split(",")
    return [str(v).strip().lower() for v in values if str(v).strip()]


class UnreadableSource(Exception):
    """Platform or profile files that do not parse, named one per line."""

    def __init__(self, sources: list[str]) -> None:
        super().__init__("\n".join(sources))
        self.sources = sources


@dataclass
class Declarations:
    """The file entries of every registered platform, and of each profile apart."""

    platform_entries: list[dict] = field(default_factory=list)
    # One list per profile: an entry's aliases are judged against its own profile.
    profile_entries: list[list[dict]] = field(default_factory=list)

    def entries(self) -> list[dict]:
        """Every declared file entry, platforms first."""
        return self.platform_entries + [
            entry for entries in self.profile_entries for entry in entries
        ]


def _read_source(path: Path, unreadable: list[str]) -> dict | None:
    """One platform or profile file, None and its name recorded when it does not read."""
    try:
        return source_yaml_file(path) or {}
    except SourceUnreadable as e:
        unreadable.append(str(e))
    except OSError as e:
        unreadable.append(f"{path}: {e}")
    return None


def read_declarations(platforms_dir: Path, emulators_dir: Path) -> Declarations:
    """Every file entry the registered platforms and the profiles declare.

    A source that does not parse is reported and the run refused: written
    without it, the database lost every alias the file proves and the
    command exited 0 (dosbox-x's wqy fonts answered not_found).
    """
    declared = Declarations()
    unreadable: list[str] = []
    if platforms_dir.is_dir():
        for name in list_registered_platforms(str(platforms_dir)):
            config = _read_source(platforms_dir / f"{name}.yml", unreadable)
            for system in ((config or {}).get("systems") or {}).values():
                declared.platform_entries.extend(system.get("files") or [])
    if emulators_dir.is_dir():
        for source in source_yaml_paths(emulators_dir):
            profile = _read_source(source, unreadable)
            if profile is not None:
                declared.profile_entries.append(profile.get("files") or [])
    if unreadable:
        raise UnreadableSource(unreadable)
    return declared
