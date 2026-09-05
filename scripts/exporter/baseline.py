"""Reconciliation of a platform's own declarations with the ground truth.

An export is not the truth rendered in a native syntax. It is the platform's
file, corrected: what the truth can prove is applied, what it says nothing
about is left alone, and what it knows and the platform lacks is added. A
platform that loses two thirds of its systems to an export cannot use it.

Systems are keyed by the identifier the platform itself uses. Several of our
slugs collapse onto one native id (Recalbox files pcengine, pcenginecd and
supergrafx under one slug) and one slug can carry several native ids, so the
grouping is rebuilt from the per-file native_system the scrapers record.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import _norm_system_id

HASH_FIELDS = ("sha1", "md5", "sha256", "crc32")


def _hash_values(entry: dict, field_name: str) -> list[str]:
    """Return a hash field as a list, whatever shape it was written in."""
    raw = entry.get(field_name)
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(v).strip().lower() for v in raw if str(v).strip()]
    return [v.strip().lower() for v in str(raw).split(",") if v.strip()]


def _is_placeholder(name: str) -> bool:
    return "<" in name or ">" in name or "*" in name


@dataclass
class NativeFile:
    """One file as the platform will read it, after correction."""

    name: str
    destination: str
    native_system: str
    platform: dict | None = None
    truth: dict | None = None
    corrections: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        if self.platform is not None and self.truth is not None:
            return "both"
        return "platform" if self.platform is not None else "truth"

    def hashes(self, field_name: str) -> list[str]:
        """Accepted values for a hash, truth first when it has an opinion.

        The truth is read from the emulator's source; the platform list is a
        secondary source. When both speak and disagree, the truth decides and
        the divergence is recorded, never silently merged: an emulator that
        rejects a file will reject it whatever the platform declares.
        """
        truth_values = _hash_values(self.truth or {}, field_name)
        platform_values = _hash_values(self.platform or {}, field_name)
        if truth_values and platform_values and not set(truth_values) & set(
            platform_values
        ):
            return truth_values
        if truth_values:
            # Keep the platform's extra accepted revisions alongside ours.
            merged = list(truth_values)
            merged.extend(v for v in platform_values if v not in merged)
            return merged
        return platform_values

    def hash(self, field_name: str) -> str:
        values = self.hashes(field_name)
        return values[0] if values else ""

    @property
    def required(self) -> bool:
        if self.truth is not None and self.truth.get("required") is not None:
            return bool(self.truth["required"])
        if self.platform is not None and self.platform.get("required") is not None:
            return bool(self.platform["required"])
        return True

    @property
    def priority(self) -> int | None:
        """Where the code looks for this file, lowest first.

        DuckStation's FindBIOSImageInDirectory keeps the image whose
        priority is lower, and a search list a core walks in order maps
        onto it as 1, 2, 3. Where cores disagree this is the best rank any
        of them gives: nothing is dropped on it, so a file that is some
        core's first choice is read early. None when nothing states one.
        """
        for entry in (self.truth, self.platform):
            if entry and entry.get("priority") is not None:
                return int(entry["priority"])
        return None

    def size(self) -> int | None:
        for entry in (self.truth, self.platform):
            if entry and entry.get("size"):
                return int(entry["size"])
        return None

    def native(self, key: str, default: object = "") -> object:
        """Read a field the platform declares and we only carry through."""
        for entry in (self.platform, self.truth):
            if entry and entry.get(key) not in (None, ""):
                return entry[key]
        return default

    def cores(self) -> list[str]:
        """Cores that want this file, the platform's naming preferred."""
        declared = self.native("core", "")
        if declared:
            return [c.strip() for c in str(declared).split(",") if c.strip()]
        if self.truth:
            return [f"libretro/{c}" for c in self.truth.get("_cores", [])]
        return []


@dataclass
class NativeSystem:
    """One system as the platform names it."""

    native_id: str
    name: str = ""
    files: list[NativeFile] = field(default_factory=list)
    from_platform: bool = False

    @property
    def origin(self) -> str:
        return "platform" if self.from_platform else "truth"


@dataclass
class Report:
    """What the reconciliation changed, so the caller can say it out loud."""

    systems_kept: int = 0
    systems_added: int = 0
    files_kept: int = 0
    files_added: int = 0
    hashes_corrected: list[str] = field(default_factory=list)
    required_corrected: list[str] = field(default_factory=list)

    @property
    def corrections(self) -> int:
        return len(self.hashes_corrected) + len(self.required_corrected)


def _native_id_of(sys_key: str, sys_data: dict, file_entry: dict) -> str:
    """The platform's own id for the system a file belongs to."""
    return (
        file_entry.get("native_system")
        or sys_data.get("native_id")
        or sys_key
    )


def _match_key(entry: dict) -> tuple[str, str]:
    dest = str(entry.get("destination") or entry.get("path") or entry.get("name", ""))
    return dest.casefold(), str(entry.get("name", "")).casefold()


def build_native_model(
    truth: dict,
    scraped: dict | None,
) -> tuple[dict[str, NativeSystem], Report]:
    """Rebuild the platform's systems, corrected by the truth.

    Returns the systems keyed by native id, in the platform's own order
    first and truth-only additions after, plus what changed.
    """
    report = Report()
    systems: dict[str, NativeSystem] = {}

    scraped_systems = (scraped or {}).get("systems", {})

    # Pass 1: the platform's own file, grouped as the platform groups it.
    for sys_key, sys_data in scraped_systems.items():
        for file_entry in sys_data.get("files", []):
            native_id = _native_id_of(sys_key, sys_data, file_entry)
            system = systems.get(native_id)
            if system is None:
                system = NativeSystem(
                    native_id=native_id,
                    name=str(file_entry.get("native_name") or sys_data.get("name", "")),
                    from_platform=True,
                )
                systems[native_id] = system
                report.systems_kept += 1
            name = str(file_entry.get("name", ""))
            destination = str(file_entry.get("destination") or name)
            system.files.append(
                NativeFile(
                    name=name,
                    destination=destination,
                    native_system=native_id,
                    platform=file_entry,
                )
            )
            report.files_kept += 1

    # Which native ids a truth system may contribute to.
    norm_to_scraped: dict[str, str] = {
        _norm_system_id(key): key for key in scraped_systems
    }
    native_by_norm: dict[str, str] = {}
    for system in systems.values():
        native_by_norm.setdefault(_norm_system_id(system.native_id), system.native_id)

    def _target_native_ids(truth_sid: str) -> list[str]:
        scraped_key = truth_sid if truth_sid in scraped_systems else None
        if scraped_key is None:
            scraped_key = norm_to_scraped.get(_norm_system_id(truth_sid))
        if scraped_key is not None:
            sys_data = scraped_systems[scraped_key]
            ids = {
                _native_id_of(scraped_key, sys_data, fe)
                for fe in sys_data.get("files", [])
            }
            if not ids:
                return [sys_data.get("native_id") or scraped_key]
            # A file the platform does not declare joins the system's primary
            # id, not whichever of its native ids sorts first: Recalbox files
            # pcengine, pcenginecd and supergrafx under one slug, and an
            # addition belongs to the one the system is named for.
            primary = sys_data.get("native_id")
            ordered = sorted(ids)
            if primary in ids:
                ordered.remove(primary)
                ordered.insert(0, primary)
            return ordered
        direct = native_by_norm.get(_norm_system_id(truth_sid))
        return [direct] if direct else [truth_sid]

    # Pass 2: apply the truth onto that grouping.
    for truth_sid in sorted(truth.get("systems", {})):
        truth_sys = truth["systems"][truth_sid]
        truth_files = truth_sys.get("files", [])
        if not truth_files:
            continue

        target_ids = _target_native_ids(truth_sid)

        for truth_entry in truth_files:
            name = str(truth_entry.get("name", ""))
            if not name or name.startswith("_") or _is_placeholder(name):
                continue

            t_dest, t_name = _match_key(truth_entry)
            t_hashes = {
                value
                for field_name in HASH_FIELDS
                for value in _hash_values(truth_entry, field_name)
            }

            candidates = [
                candidate
                for native_id in target_ids
                for candidate in systems.get(
                    native_id, NativeSystem(native_id)
                ).files
                if candidate.truth is None
            ]

            def by_destination(candidate: NativeFile) -> bool:
                theirs = _match_key(candidate.platform or {})[0]
                return bool(t_dest) and theirs == t_dest

            def by_name(candidate: NativeFile) -> bool:
                theirs = _match_key(candidate.platform or {})[1]
                return bool(t_name) and theirs == t_name

            def by_hash(candidate: NativeFile) -> bool:
                if not t_hashes:
                    return False
                theirs = {
                    value
                    for field_name in HASH_FIELDS
                    for value in _hash_values(candidate.platform or {}, field_name)
                }
                return bool(t_hashes & theirs)

            # Tried in order across every candidate, not per candidate: with
            # three IPL.bin under one system, separated only by their path, a
            # first-match-wins scan would attach the truth to whichever came
            # first and correct the wrong region's file.
            matched: NativeFile | None = None
            for test in (by_destination, by_name, by_hash):
                matched = next((c for c in candidates if test(c)), None)
                if matched is not None:
                    break

            if matched is not None:
                matched.truth = truth_entry
                for field_name in HASH_FIELDS:
                    ours = set(_hash_values(truth_entry, field_name))
                    theirs = set(_hash_values(matched.platform or {}, field_name))
                    if ours and theirs and not ours & theirs:
                        matched.corrections.append(field_name)
                        report.hashes_corrected.append(
                            f"{matched.native_system}/{matched.name} {field_name}"
                        )
                t_req = truth_entry.get("required")
                p_req = (matched.platform or {}).get("required")
                if (
                    t_req is not None
                    and p_req is not None
                    and bool(t_req) != bool(p_req)
                ):
                    matched.corrections.append("required")
                    report.required_corrected.append(
                        f"{matched.native_system}/{matched.name}"
                    )
                continue

            # The truth knows a file the platform does not declare.
            native_id = target_ids[0]
            system = systems.get(native_id)
            if system is None:
                system = NativeSystem(native_id=native_id, from_platform=False)
                systems[native_id] = system
                report.systems_added += 1
            destination = str(
                truth_entry.get("path") or truth_entry.get("destination") or name
            )
            system.files.append(
                NativeFile(
                    name=name,
                    destination=destination,
                    native_system=native_id,
                    truth=truth_entry,
                )
            )
            report.files_added += 1

    # A reader takes the files in the order the list gives, so the one the
    # code looks for first is named first. Only what we add is ordered: what
    # the platform already wrote keeps the place the platform gave it.
    for system in systems.values():
        head = [fe for fe in system.files if fe.platform is not None]
        tail = [fe for fe in system.files if fe.platform is None]
        system.files = head + search_order(tail)

    return systems, report


def search_order(files: list[NativeFile]) -> list[NativeFile]:
    """Order files the way the code looks for them, best first.

    `priority:` is that order where the source states it, lowest first.
    Where it does not, the order the entries were declared in is the order
    the code walks, so it is left alone.
    """
    ranked = [(fe.priority, position, fe) for position, fe in enumerate(files)]
    return [
        fe
        for _, _, fe in sorted(
            ranked,
            key=lambda item: (
                (0, item[0]) if item[0] is not None else (1, item[1])
            ),
        )
    ]
