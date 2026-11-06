"""Exporter for RetroDECK's component manifests.

RetroDECK has no single BIOS file. Each component carries its own
component_manifest.json, and the BIOS list sits inside it next to the
component's name, description and presets, at one of three keys. Only that
list is rewritten, in the component's own file, so everything else the
manifest drives is left alone.
"""

from __future__ import annotations

import json
from collections import OrderedDict

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report

COMPONENTS_REPO = "RetroDECK/components"
COMPONENTS_BRANCH = "main"
RAW_BASE = f"https://raw.githubusercontent.com/{COMPONENTS_REPO}/{COMPONENTS_BRANCH}"
MANIFEST = "component_manifest.json"
# Labels that only say yes or no, so a corrected requirement can be written
# over them. Every other label is a sentence ("At least one BIOS file
# required", "Required for some Japanese games.") and is the platform's own.
PLAIN_LABELS = ("Required", "Optional")


def _systems_of(entry: dict) -> list[str]:
    """The systems one entry serves: neogeo.zip is declared once for three."""
    declared = entry.get("system")
    if isinstance(declared, list):
        return [str(s) for s in declared]
    return [str(declared)] if declared else []


def _md5_set(value: object) -> set[str]:
    values = value if isinstance(value, list) else str(value or "").split(",")
    return {str(m).strip().lower() for m in values if str(m).strip()}


def _paths_key(entry: dict) -> tuple[str, ...]:
    """Where an entry says the file goes: no paths is the BIOS root."""
    paths = entry.get("paths")
    if isinstance(paths, list):
        return tuple(sorted(str(p) for p in paths))
    return (str(paths),) if paths else ()


def _matching_keys(
    entry: dict, by_key: dict[tuple[str, str], OrderedDict]
) -> list[tuple[str, str]]:
    """Our keys this platform entry answers to.

    An entry without a system matches ours only when one system alone
    declares the name.
    """
    name = str(entry.get("filename", ""))
    systems = _systems_of(entry)
    if systems:
        return [(name, s) for s in systems if (name, s) in by_key]
    named = [k for k in by_key if k[0] == name]
    return named if len(named) == 1 else []


class Exporter(BaseExporter):
    """Write RetroDECK's component manifests, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "retrodeck"

    @staticmethod
    def native_filename() -> str:
        return MANIFEST

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"md5", "sha256", "required"})

    @staticmethod
    def needs_original() -> bool:
        # A manifest is mostly presets and launch configuration, so rebuilding
        # one from BIOS data alone would throw the component away.
        return True

    @classmethod
    def writable(cls, fe: NativeFile, require: str = "") -> bool:
        """An addition lands only in a manifest it can be placed in."""
        if fe.platform is None and not fe.native("component", ""):
            return False
        return super().writable(fe, require)

    def written(self, fe: NativeFile, field_name: str) -> str:
        """md5 is a list of every accepted dump, sha256 a single value."""
        if field_name == "sha256":
            return fe.hash(field_name)
        return super().written(fe, field_name)

    def written_list(self, fe: NativeFile, field_name: str) -> list[str] | None:
        """Several md5 values are a JSON array in the manifest, as _entry
        writes them: a list the truth extended is a change the report names."""
        if field_name == "md5" and len(fe.hashes("md5")) > 1:
            return fe.hashes("md5")
        return None

    def states(self, fe: NativeFile, field_name: str) -> bool:
        if id(fe) in getattr(self, "_appended", ()):
            return False
        if field_name == "required":
            label = str(fe.native("required_label", ""))
            return not label or label in PLAIN_LABELS
        return super().states(fe, field_name)

    @staticmethod
    def _place_additions(systems: dict[str, NativeSystem]) -> None:
        """Give each addition the component its system already lives in.

        A component is one emulator's manifest, and only the platform's
        entries name it. A system whose entries all sit in one component
        takes the addition there, when a core reading the file is that
        component's emulator: armsx2's flash.dat is no file PCSX2 opens, and
        beetle_psx's scph5903.bin none DuckStation's manifest should ask for.
        One spread over several, with none of its own, or of another
        emulator cannot say which manifest is meant, and the addition is
        left out and counted as such.
        """
        for system in systems.values():
            components = {
                str(fe.native("component", ""))
                for fe in system.files
                if fe.platform is not None and fe.native("component", "")
            }
            if len(components) != 1:
                continue
            component = components.pop()
            for fe in system.files:
                if fe.platform is None and fe.truth is not None and any(
                    name == component if standalone else component == "retroarch"
                    for standalone, name in fe.runners
                ):
                    fe.truth = {**fe.truth, "component": component}

    @staticmethod
    def component_url(component: str) -> str:
        return f"{RAW_BASE}/{component}/{MANIFEST}"

    def components(self, systems: dict[str, NativeSystem]) -> list[str]:
        """Components the corrected data touches."""
        found: set[str] = set()
        for system in systems.values():
            for fe in system.files:
                component = str(fe.native("component", ""))
                if component:
                    found.add(component)
        return sorted(found)

    @staticmethod
    def _entry(fe: NativeFile) -> OrderedDict:
        entry: OrderedDict[str, object] = OrderedDict()
        entry["filename"] = fe.name
        # Several accepted dumps stay a JSON array, as RetroDECK writes them:
        # a comma-joined string reads back as one value that is no md5.
        md5 = fe.hashes("md5")
        if md5:
            entry["md5"] = md5 if len(md5) > 1 else md5[0]
        sha256 = fe.hash("sha256")
        if sha256:
            entry["sha256"] = sha256
        entry["system"] = fe.native_system
        description = fe.native("description", "")
        if description:
            entry["description"] = str(description)
        # RetroDECK words the requirement in prose ("Required", "At least one
        # BIOS file required"), so the platform's own wording is kept and a
        # boolean is only rendered when there is none to keep.
        label = str(fe.native("required_label", ""))
        if label and label not in PLAIN_LABELS:
            entry["required"] = label
        elif fe.required:
            entry["required"] = "Required"
        elif label:
            entry["required"] = "Optional"
        destination = fe.destination
        if destination and destination not in (fe.name, f"bios/{fe.name}"):
            directory = destination.rsplit("/", 1)[0]
            entry["paths"] = "$bios_path/" + directory.removeprefix("bios/")
        return entry

    def _by_component(
        self, systems: dict[str, NativeSystem]
    ) -> dict[str, list[NativeFile]]:
        grouped: dict[str, list[NativeFile]] = {}
        for system in systems.values():
            for fe in system.files:
                component = str(fe.native("component", ""))
                if component:
                    grouped.setdefault(component, []).append(fe)
        return grouped

    @staticmethod
    def _bios_holder(component_value: dict) -> tuple[dict, str] | None:
        """Where in a manifest the BIOS list lives, if it has one."""
        if "bios" in component_value:
            return component_value, "bios"
        for key in ("preset_actions", "cores"):
            nested = component_value.get(key)
            if isinstance(nested, dict) and "bios" in nested:
                return nested, "bios"
        return None

    @classmethod
    def _merge(
        cls,
        existing: object,
        ours: list[OrderedDict],
        additions: list[OrderedDict] | None = None,
        appended: set[tuple[str, str]] | None = None,
        held_back: list[int] | None = None,
    ) -> list[OrderedDict]:
        """Correct the component's own list, never replace it.

        Assigning our entries wholesale dropped every file RetroDECK declares
        that our model does not carry -- 177 of them across the components.
        An entry the platform declares is kept, its fields corrected where the
        truth has something to say and left alone where it does not, and what
        the platform does not declare is appended.
        """
        # Keyed by name AND system: the retroarch manifest declares
        # ATARIOSB.ROM for atari5200 and atari800 with different md5 lists,
        # and a name-only key wrote the first of ours over both.
        by_key: OrderedDict[tuple[str, str], OrderedDict] = OrderedDict()
        for entry in ours:
            key = (str(entry.get("filename", "")), str(entry.get("system", "")))
            if key[0] and key not in by_key:
                by_key[key] = entry

        merged: list[OrderedDict] = []
        corrected: set[tuple[str, str]] = set()
        # PPSSPP writes its one BIOS as an object, not a list of one.
        if isinstance(existing, dict):
            existing = [existing]
        entries = [e for e in existing if isinstance(e, dict)] if isinstance(existing, list) else []
        # A name and system declared several times are several revisions (the
        # 64DD IPL USA and Dev): one entry of ours corrects the revision it
        # shares a hash with, never all of them.
        seen_keys: dict[tuple[str, str], int] = {}
        for entry in entries:
            for system in _systems_of(entry):
                key = (str(entry.get("filename", "")), system)
                seen_keys[key] = seen_keys.get(key, 0) + 1
        # A hash no revision shares is a revision the platform does not
        # know: appended, not counted corrected against entries kept as
        # they were (the 64DD IPL declared twice, both contradicted).
        for entry in entries:
            keys = _matching_keys(entry, by_key)
            other_revision = (
                keys
                and seen_keys.get(keys[0], 0) > 1
                and not _md5_set(entry.get("md5")) & _md5_set(by_key[keys[0]].get("md5"))
            )
            if other_revision or not keys:
                merged.append(OrderedDict(entry))
                continue
            declared = entry.get("system")
            combined = OrderedDict(entry)
            # Only what the format says it corrects: the maintainer's
            # description and search paths are theirs (neogeo.zip lost its
            # four roms directories to a path that does not exist).
            combined.update(
                (field, value) for field, value in by_key[keys[0]].items()
                if field in cls.carries() and not (field == "system" and declared)
            )
            # A hash of theirs that ours no longer carries is one the truth
            # contradicts: kept, it went on rejecting the dump the emulator
            # loads while the summary counted it cleared.
            for field in ("md5", "sha256"):
                if field in cls.carries() and field not in by_key[keys[0]]:
                    combined.pop(field, None)
            if _md5_set(entry.get("md5")) == _md5_set(combined.get("md5")):
                # Their own spelling, and no key where they wrote none: an
                # equal empty set wrote "md5": null 39 times.
                if "md5" in entry:
                    combined["md5"] = entry["md5"]
                else:
                    combined.pop("md5", None)
            elif isinstance(entry.get("md5"), list) and isinstance(combined.get("md5"), str):
                combined["md5"] = [combined["md5"]]
            merged.append(combined)
            corrected.update(keys)

        uncorrected = [key for key in by_key if key not in corrected]
        merged.extend(by_key[key] for key in uncorrected)
        if appended is not None:
            appended.update(uncorrected)
        # A file the platform does not declare is appended unless the list
        # already holds that name for that system at that path. The key
        # above is name and system only, and folded melonDS's SkyEmu/
        # firmware.bin into the root firmware.bin the platform declares,
        # while the report counted it added.
        held = {
            (str(e.get("filename", "")), system, _paths_key(e))
            for e in merged
            for system in (_systems_of(e) or [""])
        }
        for index, entry in enumerate(additions or []):
            key = (str(entry.get("filename", "")), str(entry.get("system", "")), _paths_key(entry))
            if key[0] and key not in held:
                held.add(key)
                merged.append(entry)
            elif held_back is not None:
                held_back.append(index)
        return merged

    def lands(self, fe: NativeFile) -> bool:
        """An addition the list already held is not written a second time."""
        return self.writable(fe) and id(fe) not in getattr(self, "_held_back", set())

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        self._place_additions(systems)
        self._appended: set[int] = set()
        self._held_back: set[int] = set()
        grouped = self._by_component(systems)
        produced: dict[str, str] = {}

        for component, files in sorted(grouped.items()):
            path = f"{component}/{MANIFEST}"
            original = originals.get(path)
            if not original:
                continue
            try:
                manifest = json.loads(original, object_pairs_hook=OrderedDict)
            except json.JSONDecodeError:
                continue

            entries = [self._entry(fe) for fe in files if fe.platform is not None]
            added = [fe for fe in files if fe.platform is None]
            additions = [self._entry(fe) for fe in added]
            appended: set[tuple[str, str]] = set()
            held_back: list[int] = []
            for component_value in manifest.values():
                if not isinstance(component_value, dict):
                    continue
                holder = self._bios_holder(component_value)
                if holder is None:
                    component_value["bios"] = self._merge(
                        None, entries, additions, appended, held_back
                    )
                else:
                    container, key = holder
                    written = container.get(key)
                    merged = self._merge(written, entries, additions, appended, held_back)
                    # A single object stays one while nothing is added to it.
                    container[key] = (
                        merged[0] if isinstance(written, dict) and len(merged) == 1 else merged
                    )
                break
            self._held_back.update(id(added[index]) for index in held_back)
            # A declared entry whose revision the platform does not hold is
            # written beside theirs: a new line, not a corrected value.
            self._appended.update(
                id(fe) for fe in files
                if fe.platform is not None
                and (str(fe.name), str(fe.native_system)) in appended
            )

            # Nine of ten manifests end without a newline: the file ends as
            # theirs does.
            ending = "\n" if original.endswith("\n") else ""
            produced[path] = json.dumps(manifest, indent=2, ensure_ascii=False) + ending

        return produced

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        issues: list[str] = []
        grouped = self._by_component(systems)

        for component, files in grouped.items():
            path = f"{component}/{MANIFEST}"
            if path not in produced:
                issues.append(f"manifest not written: {path}")
                continue
            try:
                manifest = json.loads(produced[path])
            except json.JSONDecodeError as exc:
                issues.append(f"{path} does not parse: {exc}")
                continue

            declared: set[str] = set()
            placed: set[tuple[str, tuple[str, ...]]] = set()
            for component_value in manifest.values():
                if not isinstance(component_value, dict):
                    continue
                holder = self._bios_holder(component_value)
                if holder is None:
                    continue
                container, key = holder
                listed = container[key]
                for entry in [listed] if isinstance(listed, dict) else listed:
                    declared.add(entry.get("filename", ""))
                    placed.add((entry.get("filename", ""), _paths_key(entry)))
                if not component_value.get("name") and not component_value.get(
                    "system"
                ):
                    issues.append(f"{path}: the component lost its identity")

            for fe in files:
                if fe.name not in declared:
                    issues.append(f"absent from {path}: {fe.name}")
                elif fe.platform is None and (
                    fe.name, _paths_key(self._entry(fe))
                ) not in placed:
                    issues.append(f"absent from {path}: {fe.destination or fe.name}")
        return issues
