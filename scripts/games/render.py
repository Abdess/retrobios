"""Every file of install/games/ rendered to its text, with index.json and the coverage."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from games.arcadesets import build_arcade
from games.folders import folder_systems
from games.inputs import FORMAT_VERSION, OUTPUT, Inputs, load_optional_yaml
from games.profileindex import Profiles
from games.setups import build_setups
from games.systems import build_systems
from model.profiles import load_emulator_profiles
from model.romfolders import ProfileResolver, SystemResolver, load_setups


def dumps(document: object) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def _entry(text: str) -> dict:
    data = text.encode("utf-8")
    return {
        "size": len(data),
        "gzip_size": len(gzip.compress(data, compresslevel=9, mtime=0)),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def render(output: Path = OUTPUT, inputs: Inputs | None = None) -> tuple[dict[Path, str], dict]:
    """Every published file's text, keyed by its path, and the coverage."""
    inputs = inputs or Inputs()
    resolver = SystemResolver.from_repo(inputs.emulators, inputs.platforms)
    profiles = Profiles(load_emulator_profiles(inputs.emulators), resolver)
    arcade = build_arcade(inputs.games / "arcade")
    setups, fallbacks, setup_cov = build_setups(
        load_setups(inputs.romfolders), resolver, ProfileResolver.from_repo(inputs.emulators),
        profiles, set(arcade), inputs,
    )
    used: dict[str, set[str]] = {}
    for doc in setups.values():
        for row in doc["folders"]:
            for system in row["systems"]:
                if row.get("profile"):
                    used.setdefault(system, set()).add(row["profile"])
    systems, system_cov = build_systems(resolver, profiles, used, inputs.games)

    files: dict[Path, str] = {}
    index: dict = {"format_version": FORMAT_VERSION, "setups": {}, "fallback": {}, "systems": {}, "arcade": {}}
    for kind, docs in (("setups", setups), ("fallback", fallbacks), ("systems", systems), ("arcade", arcade)):
        for key, doc in sorted(docs.items()):
            rel = Path(kind) / f"{key}.json"
            text = dumps(doc)
            files[output / rel] = text
            index[kind][key] = {"file": rel.as_posix(), **_entry(text)}
    digest = hashlib.sha256(
        "".join(f"{p.relative_to(output).as_posix()} {_entry(t)['sha256']}\n" for p, t in sorted(files.items())).encode()
    ).hexdigest()
    index["data_version"] = digest[:16]
    index["licences"] = sorted(
        {json.dumps(src.get("licence"), sort_keys=True)
         for doc in systems.values() for src in doc.get("identify", {}).get("sources", [])
         if src.get("licence")}
    )
    index["licences"] = [json.loads(x) for x in index["licences"]]
    containers = load_optional_yaml(inputs.games / "headers.yml").get("containers")
    if containers:
        index["containers"] = containers
    index["folders"] = folder_systems(setups)
    files[output / "index.json"] = dumps(index)
    coverage = {"setups": setup_cov, "systems": system_cov, "arcade": sorted(arcade)}
    return files, coverage
