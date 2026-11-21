"""What an export changed in a platform's file, field by field, with each
value before and after."""

from __future__ import annotations

from dataclasses import dataclass, field

from .base_exporter import BaseExporter
from core.hashing import parse_hash_list
from resolve.reconcile import HASH_FIELDS, NativeFile, single_size


@dataclass
class LandedChanges:
    """What an export changed in the platform's file, field by field.

    `records` holds each change with its value before and after, so a
    maintainer can check it against the diff. The lists of labels are read
    from it, for the summary and the page.
    """

    records: list[dict] = field(default_factory=list)

    def _labels(self, kind: str) -> list[str]:
        return [
            f"{r['system']}/{r['name']} {r['field']}"
            for r in self.records if r["kind"] == kind
        ]

    @property
    def applied(self) -> list[str]:
        return self._labels("hash_updated")

    @property
    def filled(self) -> list[str]:
        return self._labels("hash_filled")

    @property
    def cleared(self) -> list[str]:
        return self._labels("hash_cleared")

    @property
    def resized(self) -> list[str]:
        return [label.removesuffix(" size") for label in self._labels("size_updated")]

    @property
    def unsized(self) -> list[str]:
        return [label.removesuffix(" size") for label in self._labels("size_removed")]

    @property
    def requirements(self) -> int:
        return sum(r["kind"] == "required_aligned" for r in self.records)

    @property
    def lists(self) -> int:
        """Entries whose md5 is written as a list of accepted values."""
        return sum(
            isinstance(r["new"], list)
            or (isinstance(r["new"], dict) and isinstance(r["new"].get("md5"), list))
            for r in self.records
        )


def _change(
    kind: str, entry: NativeFile, field_name: str | None, old: object, new: object
) -> dict:
    return {
        "kind": kind,
        "system": entry.native_system,
        "name": entry.name,
        "destination": entry.destination,
        "field": field_name,
        "old": old,
        "new": new,
    }


def _platform_value(entry: NativeFile, field_name: str) -> str | list[str]:
    values = parse_hash_list((entry.platform or {}).get(field_name))
    if (entry.platform or {}).get(f"{field_name}_list"):
        return values
    return ",".join(values)


def _written_value(exporter: BaseExporter, entry: NativeFile, field_name: str) -> str | list[str]:
    """A hash field as the render writes it: a list where the checker reads
    one, so the report never shows several values as one."""
    listed = exporter.written_list(entry, field_name)
    return listed if listed is not None else exporter.written(entry, field_name)


def _added_fields(exporter: BaseExporter, entry: NativeFile) -> dict:
    """The fields an addition is written with, as the render chooses them."""
    carried = exporter.carries()
    written: dict[str, object] = {
        name: value
        for name in HASH_FIELDS
        if name in carried and (value := _written_value(exporter, entry, name))
    }
    if "size" in carried and entry.size() is not None:
        written["size"] = entry.size()
    if "required" in carried:
        written["required"] = exporter.required_value(entry)
    return written


def landed_changes(exporter: BaseExporter, systems: dict) -> LandedChanges:
    """The changes the written file carries, with their values.

    Only what the format states: a correction to a field the file has no
    place for, or one its render keeps out, is not a change the maintainer
    will find in the diff, and counting it would announce work the export
    did not do. A hash written where the platform left none changes the
    check from existence to content, so it is counted too. The truth taking
    over an entry also rewrites its size and drops the platform's hashes it
    does not declare: both are in the diff. An addition carries the fields
    it is written with as its new value.
    """
    changes = LandedChanges()
    records = changes.records
    for system in systems.values():
        for entry in system.files:
            if entry.platform is None:
                if entry.name and exporter.lands(entry):
                    records.append(_change(
                        "added", entry, None, None, _added_fields(exporter, entry)
                    ))
                continue
            if entry.name and exporter.names_anew(entry):
                records.append(_change(
                    "added", entry, None, None, _added_fields(exporter, entry)
                ))
            # Asked of the exporter: a format that names each entry's cores
            # reads every entry of those cores, not only the paired one.
            if (
                entry.platform.get("required") is not None
                and exporter.states(entry, "required")
                and exporter.required_value(entry) != bool(entry.platform["required"])
            ):
                records.append(_change(
                    "required_aligned", entry, "required",
                    bool(entry.platform["required"]), exporter.required_value(entry),
                ))
            for field_name in entry.corrections:
                if field_name == "required" or not exporter.states(entry, field_name):
                    continue
                records.append(_change(
                    "hash_updated", entry, field_name,
                    _platform_value(entry, field_name),
                    _written_value(exporter, entry, field_name),
                ))
            # A list the truth extends with values the platform's own lacks:
            # no contradiction, so no correction in the model, and still a
            # new value in the file.
            for field_name in HASH_FIELDS:
                listed = exporter.written_list(entry, field_name)
                if (
                    listed is not None
                    and field_name not in entry.corrections
                    and field_name not in entry.filled
                    and listed != parse_hash_list(entry.platform.get(field_name))
                    and exporter.states(entry, field_name)
                ):
                    records.append(_change(
                        "hash_updated", entry, field_name,
                        _platform_value(entry, field_name), listed,
                    ))
            records.extend(
                _change("hash_filled", entry, field_name, None,
                        _written_value(exporter, entry, field_name))
                for field_name in entry.filled
                if exporter.fills(entry, field_name)
            )
            theirs = entry.platform.get("size")
            ours = entry.size()
            if (
                theirs
                and ours
                and single_size(theirs) not in (None, ours)
                and exporter.states(entry, "size")
            ):
                records.append(_change(
                    "size_updated", entry, "size", single_size(theirs), ours
                ))
            elif (
                theirs
                and ours is None
                and single_size(theirs) is not None
                and exporter.states(entry, "size")
            ):
                # The truth took the entry over without a size of its own:
                # System.dat's neocdz.zip line went out without size 953078.
                records.append(_change(
                    "size_removed", entry, "size", single_size(theirs), None
                ))
            records.extend(
                _change("hash_cleared", entry, field_name,
                        _platform_value(entry, field_name), None)
                for field_name in HASH_FIELDS
                if parse_hash_list(entry.platform.get(field_name))
                and not entry.hashes(field_name)
                and exporter.clears(entry, field_name)
            )
    # A value the render rewrote though the model reads it as the
    # platform's own (RomM's sha1 with a leading space).
    records.extend(
        _change("hash_updated", entry, field_name, old, new)
        for entry, field_name, old, new in getattr(exporter, "normalized_values", [])
    )
    return changes
