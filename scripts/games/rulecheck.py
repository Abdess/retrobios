"""The checks of games/regions.yml and games/extras.yml against the profiles and the header readers."""

from __future__ import annotations

import re
from dataclasses import dataclass

from games.headerreaders import header_readers, reader_answers
from games.profileindex import declared_names, every_tag, profile_pins, tagged_regions
from model.region import REGIONS

_REF_REPO = re.compile(r"(?:^|; )([\w.-]+/[\w.-]+)@([0-9a-f]{8,40}) ")


@dataclass
class Checker:
    profiles: dict[str, dict]
    readers: dict[str, dict] | None = None

    def __post_init__(self) -> None:
        self.errors: list[str] = []

    def _profile(self, where: str, name: str, system: str) -> dict | None:
        profile = self.profiles.get(name)
        if profile is None:
            self.errors.append(f"{where}: no profile {name}")
            return None
        if system not in (profile.get("systems") or []):
            self.errors.append(f"{where}: {name} does not declare system {system}")
        return profile

    def _files(self, where: str, name: str, profile: dict, files: list[str]) -> None:
        known = declared_names(profile)
        for file in files:
            if file not in known:
                self.errors.append(f"{where}: {name} declares no file {file}")

    def _region(self, where: str, value: str) -> None:
        if value not in REGIONS:
            self.errors.append(f"{where}: unknown region {value}")

    def _ref(self, where: str, profile: dict, ref: str | None) -> None:
        if not ref:
            self.errors.append(f"{where}: no source_ref")
            return
        pins = profile_pins(profile)
        cited = _REF_REPO.findall(ref)
        if not cited:
            self.errors.append(f"{where}: source_ref names no owner/repo@sha")
        for repo, sha in cited:
            if not any(pin.startswith(sha) for pin in pins):
                self.errors.append(f"{where}: {repo}@{sha} is not a pin of the profile")

    def regions(self, doc: dict) -> None:
        cases = doc.get("cases") or {}
        for system, cores in (doc.get("systems") or {}).items():
            for name, rule in cores.items():
                where = f"regions {system}/{name}"
                profile = self._profile(where, name, system)
                if profile is None:
                    continue
                self._ref(where, profile, rule.get("source_ref"))
                tags = every_tag(profile)
                for src, dst in (rule.get("routes") or {}).items():
                    self._region(where, src)
                    self._region(where, dst)
                    if dst not in tags:
                        self.errors.append(f"{where}: route {src} -> {dst}, but no file is tagged {dst}")
                for value in [rule.get("default_region"), *(rule.get("preference") or [])]:
                    if value:
                        self._region(where, value)
                free = rule.get("region_free") or []
                self._files(where, name, profile, free)
                for file in free:
                    specific = tagged_regions(profile, file) - {"world"}
                    if specific:
                        self.errors.append(
                            f"{where}: region_free {file} is tagged {sorted(specific)} in the profile"
                        )
                for keep in rule.get("keep_all_regions") or []:
                    kwhere = f"{where} case {keep.get('case')}"
                    if keep.get("case") not in cases:
                        self.errors.append(f"{kwhere}: case not described under cases")
                    self._ref(kwhere, profile, keep.get("source_ref"))
                    self._files(kwhere, name, profile, keep.get("files") or [])

    def extras(self, doc: dict) -> None:
        for index, entry in enumerate(doc.get("extras") or []):
            where = f"extras[{index}] {entry.get('system')}/{entry.get('profile')}"
            profile = self._profile(where, entry["profile"], entry["system"])
            if profile is None:
                continue
            self._ref(where, profile, entry.get("source_ref"))
            self._files(where, entry["profile"], profile, entry.get("files") or [])
            header = (entry.get("trigger") or {}).get("header")
            if header and self.readers is not None:
                self._header(where, header, self.readers)

    def _header(self, where: str, header: dict, readers: dict[str, dict]) -> None:
        reader = readers.get(header["reader"])
        if reader is None:
            self.errors.append(f"{where}: games/headers.yml has no reader {header['reader']}")
            return
        field = header.get("field")
        if field and field not in (reader.get("fields") or {}):
            self.errors.append(f"{where}: reader {header['reader']} has no field {field}")
            return
        answers = reader_answers(reader, field)
        if answers is None:
            return
        for value in header.get("values") or []:
            if value not in answers:
                self.errors.append(
                    f"{where}: reader {header['reader']} never returns {value!r}"
                )


def check(
    regions: dict, extras: dict, profiles: dict[str, dict], headers: dict | None = None
) -> list[str]:
    """Errors over both files. Without headers, header triggers go unchecked."""
    checker = Checker(profiles, header_readers(headers) if headers is not None else None)
    checker.regions(regions)
    checker.extras(extras)
    return checker.errors
