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
        label = fe.native("required_label", "")
        if label:
            entry["required"] = str(label)
        elif fe.required:
            entry["required"] = "Required"
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

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
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
                    component_value["bios"] = entries
                else:
                    container, key = holder
                    container[key] = entries
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
