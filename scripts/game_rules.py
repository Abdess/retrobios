"""Load and check games/regions.yml and games/extras.yml against the profiles.

    python scripts/game_rules.py            # check, print a summary
    python scripts/game_rules.py --json     # the summary as JSON

Both files name profiles and the files those profiles declare. A rule is
only as good as that link: a profile renamed, a file dropped from it, a
region slug the vocabulary does not know, a citation at a revision the
profile is not pinned to, or a header trigger asking a reader of
games/headers.yml for a value it never returns, and the installer would act
on a rule nothing backs. Each of those is an error here.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from common import load_emulator_profiles
from region import REGIONS, normalize_declared
from safeparse import yaml_load

REGIONS_FILE = Path("games") / "regions.yml"
EXTRAS_FILE = Path("games") / "extras.yml"
HEADERS_FILE = Path("games") / "headers.yml"

_REF_REPO = re.compile(r"(?:^|; )([\w.-]+/[\w.-]+)@([0-9a-f]{8,40}) ")


def load_yaml(path: Path) -> dict:
    with Path(path).open(encoding="utf-8") as handle:
        return yaml_load(handle) or {}


def profile_pins(profile: dict) -> set[str]:
    """Every commit a profile is pinned to, a build-mode dict included."""
    pins: set[str] = set()
    for key in ("source_commit", "upstream_commit"):
        value = profile.get(key)
        values = value.values() if isinstance(value, dict) else [value]
        pins.update(str(v) for v in values if v)
    return pins


def declared_names(profile: dict) -> set[str]:
    """The names and aliases a profile's files answer to."""
    names: set[str] = set()
    for entry in profile.get("files") or []:
        if isinstance(entry, dict) and entry.get("name"):
            names.add(str(entry["name"]))
            names.update(str(a) for a in entry.get("aliases") or [])
    return names


def tagged_regions(profile: dict, name: str) -> set[str]:
    """The regions a profile tags a file with, over all its declarations."""
    out: set[str] = set()
    for entry in profile.get("files") or []:
        if isinstance(entry, dict) and (
            entry.get("name") == name or name in (entry.get("aliases") or [])
        ):
            out |= normalize_declared(entry.get("region"))
    return out


def every_tag(profile: dict) -> set[str]:
    return {
        region
        for entry in profile.get("files") or []
        if isinstance(entry, dict)
        for region in normalize_declared(entry.get("region"))
    }


def header_readers(headers: dict) -> dict[str, dict]:
    """Every reader of games/headers.yml by id, over all its systems."""
    readers: dict[str, dict] = {}
    for system in (headers.get("systems") or {}).values():
        readers.update(system.get("readers") or {})
    return readers


def reader_answers(reader: dict, field: str | None = None) -> set[object] | None:
    """The labels and values a reader can return, None when any string can
    be (a serial or product id read as it stands)."""
    if field:
        spec = (reader.get("fields") or {}).get(field) or {}
        return {v for k, v in spec.items() if k not in ("encoding",) and isinstance(v, str)}
    decode = reader.get("decode") or {}
    if decode.get("kind") == "serial":
        return None
    answers: set[object] = set()
    for row in decode.get("values") or []:
        answers.update(row[k] for k in ("value", "label") if k in row)
    for key in ("then", "otherwise"):
        branch = decode.get(key)
        if isinstance(branch, dict) and "label" in branch:
            answers.add(branch["label"])
        elif isinstance(branch, str):
            answers.add(branch)
    return answers


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
                self._header(where, header)

    def _header(self, where: str, header: dict) -> None:
        reader = self.readers.get(header["reader"])
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


def summary(regions: dict, extras: dict) -> dict:
    keeps = [
        {"case": keep["case"], "system": system, "profile": name, "condition": keep["condition"]}
        for system, cores in sorted((regions.get("systems") or {}).items())
        for name, rule in sorted(cores.items())
        for keep in rule.get("keep_all_regions") or []
    ]
    systems = regions.get("systems") or {}
    return {
        "region_systems": len(systems),
        "region_cores": sum(len(c) for c in systems.values()),
        "cases": sorted(regions.get("cases") or {}),
        "case_entries": keeps,
        "extras": len(extras.get("extras") or []),
        "extra_systems": sorted({e["system"] for e in extras.get("extras") or []}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--regions", type=Path, default=REGIONS_FILE,
                        help=f"region rules to check (default {REGIONS_FILE})")
    parser.add_argument("--extras", type=Path, default=EXTRAS_FILE,
                        help=f"extra-file rules to check (default {EXTRAS_FILE})")
    parser.add_argument("--headers", type=Path, default=HEADERS_FILE,
                        help=f"header readers the triggers name (default {HEADERS_FILE})")
    parser.add_argument("--emulators-dir", default="emulators",
                        help="profiles the rules are checked against (default emulators)")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = parser.parse_args()
    from common import work_from_repo_root  # noqa: PLC0415

    work_from_repo_root(args, parser, ["regions", "extras", "headers", "emulators_dir"])

    regions = load_yaml(args.regions)
    extras = load_yaml(args.extras)
    errors = check(regions, extras, load_emulator_profiles(args.emulators_dir), load_yaml(args.headers))
    info = summary(regions, extras)
    if args.json:
        print(json.dumps({**info, "errors": errors}, indent=2))
    else:
        print(
            f"Region rules: {info['region_cores']} cores over {info['region_systems']} systems, "
            f"{len(info['cases'])} cases in {len(info['case_entries'])} entries"
        )
        for row in info["case_entries"]:
            print(f"  {row['case']:26} {row['system']:20} {row['profile']:22} {row['condition']}")
        print(f"Per-game extras: {info['extras']} entries over {len(info['extra_systems'])} systems")
        for error in errors:
            print(f"ERROR {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
