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
        # A manifest is mostly presets and launch configuration; rebuilding
        # one from BIOS data alone would throw the component away.
        return True

    @classmethod
    def writable(cls, fe: NativeFile, require: str = "") -> bool:
        """An addition lands only in a manifest it can be placed in."""
        if fe.platform is None and not fe.native("component", ""):
            return False
        return super().writable(fe, require)

    def states(self, fe: NativeFile, field_name: str) -> bool:
        if field_name == "required":
            label = str(fe.native("required_label", ""))
            return not label or label in PLAIN_LABELS
        return super().states(fe, field_name)

    @staticmethod
    def _place_additions(systems: dict[str, NativeSystem]) -> None:
        """Give each addition the component its system already lives in.

        A component is one emulator's manifest, and only the platform's
        entries name it. A system whose entries all sit in one component
        takes the addition there; one spread over several, or with none of
        its own, cannot say which manifest is meant, and the addition is
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
                if fe.platform is None and fe.truth is not None:
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
        md5 = ",".join(fe.hashes("md5"))
        if md5:
            entry["md5"] = md5
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

    @staticmethod
    def _merge(existing: object, ours: list[OrderedDict]) -> list[OrderedDict]:
        """Correct the component's own list; never replace it.

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
        for entry in existing if isinstance(existing, list) else []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("filename", ""))
            declared = entry.get("system")
            # One entry can serve several systems: neogeo.zip is declared
            # once for neogeo, fbneo and arcade.
            systems = (
                [str(s) for s in declared] if isinstance(declared, list)
                else [str(declared)] if declared else []
            )
            keys = [(name, s) for s in systems if (name, s) in by_key]
            if not systems:
                # An entry without a system matches ours only when one
                # system alone declares the name.
                named = [k for k in by_key if k[0] == name]
                keys = named if len(named) == 1 else []
            if not keys:
                merged.append(OrderedDict(entry))
                continue
            combined = OrderedDict(entry)
            combined.update(
                (field, value) for field, value in by_key[keys[0]].items()
                if not (field == "system" and declared)
            )
            merged.append(combined)
            corrected.update(keys)

        merged.extend(
            entry for key, entry in by_key.items() if key not in corrected
        )
        return merged

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        self._place_additions(systems)
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

            entries = [self._entry(fe) for fe in files]
            for component_value in manifest.values():
                if not isinstance(component_value, dict):
                    continue
                holder = self._bios_holder(component_value)
                if holder is None:
                    component_value["bios"] = self._merge(None, entries)
                else:
                    container, key = holder
                    container[key] = self._merge(container.get(key), entries)
                break

            produced[path] = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"

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
            for component_value in manifest.values():
                if not isinstance(component_value, dict):
                    continue
                holder = self._bios_holder(component_value)
                if holder is None:
                    continue
                container, key = holder
                for entry in container[key]:
                    declared.add(entry.get("filename", ""))
                if not component_value.get("name") and not component_value.get(
                    "system"
                ):
                    issues.append(f"{path}: the component lost its identity")

            for fe in files:
                if fe.name not in declared:
                    issues.append(f"absent from {path}: {fe.name}")
        return issues
