"""What a fresh scrape changes in a platform or target file."""

from __future__ import annotations

from dataclasses import dataclass, field

from freshness.findings import SHOWN_ITEMS


@dataclass
class PlatformDiff:
    """What a fresh scrape changes in a platform or target file."""

    version: tuple[str, str] | None = None
    systems_added: list[str] = field(default_factory=list)
    systems_removed: list[str] = field(default_factory=list)
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    cores_added: list[str] = field(default_factory=list)
    cores_removed: list[str] = field(default_factory=list)
    # Any other field the scrape writes: launchers, dual_mode_cores, a
    # system's core, native_id or data_directories.
    fields_changed: list[str] = field(default_factory=list)

    @property
    def content_changed(self) -> bool:
        return any(
            (
                self.systems_added,
                self.systems_removed,
                self.files_added,
                self.files_removed,
                self.files_changed,
                self.cores_added,
                self.cores_removed,
                self.fields_changed,
            )
        )

    @property
    def changed(self) -> bool:
        return self.content_changed or self.version is not None

    def summary(self) -> str:
        parts: list[str] = []
        if self.version:
            parts.append(f"version {self.version[0]} -> {self.version[1]}")
        for label, items in (
            ("+systems", self.systems_added),
            ("-systems", self.systems_removed),
            ("+files", self.files_added),
            ("-files", self.files_removed),
            ("~files", self.files_changed),
            ("+cores", self.cores_added),
            ("-cores", self.cores_removed),
            ("~fields", self.fields_changed),
        ):
            if items:
                shown = ", ".join(items[:SHOWN_ITEMS]) + (", ..." if len(items) > SHOWN_ITEMS else "")
                parts.append(f"{label} {len(items)} ({shown})")
        return "; ".join(parts) if parts else "identical"


def _file_key(entry: dict) -> str:
    return str(entry.get("destination") or entry.get("name") or "")


def _core_names(config: dict) -> set[str]:
    cores = config.get("cores")
    names = set(map(str, cores)) if isinstance(cores, list) else set()
    standalone = config.get("standalone_cores")
    if isinstance(standalone, list):
        names.update(f"standalone:{c}" for c in standalone)
    return names


def _keyed_files(files: list[dict]) -> dict[str, dict]:
    """Each declaration under its own key.

    A platform declares one destination several times (an archive once per
    inner ROM, MD5 alternatives): keyed by destination alone, the dict kept
    the last and a change to the others read as identical.
    """
    keyed: dict[str, dict] = {}
    seen: dict[str, int] = {}
    for f in files:
        key = _file_key(f)
        seen[key] = seen.get(key, 0) + 1
        keyed[key if seen[key] == 1 else f"{key}#{seen[key]}"] = f
    return keyed


# Compared on their own above. `source` is the revision read: it moves with
# every upstream commit, and what that commit changes is diffed field by field.
_DIFFED_APART = frozenset({"version", "systems", "cores", "standalone_cores", "source"})


def _without_refs(value: object) -> object:
    """*value* without its `source_ref` lines.

    A launcher cites lines of the revision read, so they shift with any
    upstream commit above them (es_features.cfg:11638 read as :11649 one
    RetroBat commit later). The cited content is what is compared.
    """
    if isinstance(value, dict):
        return {k: _without_refs(v) for k, v in value.items() if k != "source_ref"}
    if isinstance(value, list):
        return [_without_refs(v) for v in value]
    return value


def _changed_fields(old: dict, new: dict, skip: frozenset[str], prefix: str = "") -> list[str]:
    return [
        f"{prefix}{key}"
        for key in sorted(set(old) | set(new), key=str)
        if key not in skip and _without_refs(old.get(key)) != _without_refs(new.get(key))
    ]


def diff_platform(old: dict, new: dict) -> PlatformDiff:
    """Compare two platform files the way a reviewer reads the diff.

    Files are keyed by system and destination, so a hash or flag change on
    an existing destination is a change, not a removal plus an addition.
    """
    diff = PlatformDiff()
    old_version, new_version = str(old.get("version", "")), str(new.get("version", ""))
    if old_version != new_version:
        diff.version = (old_version, new_version)
    old_systems = old.get("systems") or {}
    new_systems = new.get("systems") or {}
    diff.systems_added = sorted(set(new_systems) - set(old_systems))
    diff.systems_removed = sorted(set(old_systems) - set(new_systems))
    for system in sorted(set(old_systems) & set(new_systems)):
        old_files = _keyed_files((old_systems[system] or {}).get("files") or [])
        new_files = _keyed_files((new_systems[system] or {}).get("files") or [])
        diff.files_added.extend(
            f"{system}/{k}" for k in sorted(set(new_files) - set(old_files))
        )
        diff.files_removed.extend(
            f"{system}/{k}" for k in sorted(set(old_files) - set(new_files))
        )
        diff.files_changed.extend(
            f"{system}/{k}"
            for k in sorted(set(old_files) & set(new_files))
            if old_files[k] != new_files[k]
        )
        diff.fields_changed.extend(_changed_fields(
            old_systems[system] or {}, new_systems[system] or {},
            frozenset({"files"}), f"{system}/",
        ))
    diff.fields_changed = _changed_fields(old, new, _DIFFED_APART) + diff.fields_changed
    old_cores, new_cores = _core_names(old), _core_names(new)
    diff.cores_added = sorted(new_cores - old_cores)
    diff.cores_removed = sorted(old_cores - new_cores)
    return diff


def diff_targets(old: dict, new: dict) -> PlatformDiff:
    """Compare two target files. The scrape stamp is not a change."""
    diff = PlatformDiff()
    old_targets = old.get("targets") or {}
    new_targets = new.get("targets") or {}
    diff.systems_added = sorted(set(new_targets) - set(old_targets))
    diff.systems_removed = sorted(set(old_targets) - set(new_targets))
    for name in sorted(set(old_targets) & set(new_targets)):
        before = set(map(str, (old_targets[name] or {}).get("cores") or []))
        after = set(map(str, (new_targets[name] or {}).get("cores") or []))
        diff.cores_added.extend(f"{name}/{c}" for c in sorted(after - before))
        diff.cores_removed.extend(f"{name}/{c}" for c in sorted(before - after))
    return diff
