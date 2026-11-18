"""The per-target core lists the installer reads."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from core.artifacts import write_text_atomic
from model.safeparse import yaml_load
from model.targets import load_target_config


def generate_target_manifests(targets_dir: str, output_dir: str) -> None:
    """Convert target YAMLs to installer JSON manifests."""
    os.makedirs(output_dir, exist_ok=True)
    targets_path = Path(targets_dir)
    if not targets_path.is_dir():
        print(f"No targets directory at {targets_dir}", file=sys.stderr)
        return
    count = 0
    for yml_file in sorted(targets_path.glob("*.yml")):
        if yml_file.name.startswith("_"):
            continue
        result = target_list(yml_file)
        out_path = Path(output_dir) / f"{yml_file.stem}.json"
        write_text_atomic(out_path, json.dumps(result, indent=2, sort_keys=True) + "\n")
        count += 1
        print(f"  {yml_file.stem}: {len(result)} targets")
    print(f"Generated {count} target manifest(s) in {output_dir}")


def target_list(yml_file: Path) -> dict[str, list[str] | dict | None]:
    """A platform's cores per hardware target, as install/targets/ publishes
    them and a pack carries them: aliases included, overrides applied."""
    targets_path = yml_file.parent
    with open(yml_file) as f:
        data = yaml_load(f) or {}
    targets = data.get("targets", {})
    if not isinstance(targets, dict):
        raise ValueError(f"{yml_file}: targets must be a mapping")

    # The pack builder accepts the aliases declared in _overrides.yml, so
    # --target switch works there. Emitting only canonical names left the
    # installer rejecting the same word and, worse, carrying on with every
    # file instead: the user asked for a filter and got the full pack.
    overrides_path = targets_path / "_overrides.yml"
    alias_map: dict[str, list[str]] = {}
    platform_overrides: dict = {}
    if overrides_path.is_file():
        with open(overrides_path) as f:
            all_overrides = yaml_load(f) or {}
        platform_overrides = (
            all_overrides.get(yml_file.stem, {}).get("targets", {}) or {}
        )
        for tname, ovr in platform_overrides.items():
            names = [a for a in (ovr or {}).get("aliases", []) if isinstance(a, str)]
            if names:
                alias_map[tname] = names

    result: dict[str, list[str] | dict | None] = {}
    for target_name, target_info in targets.items():
        if not isinstance(target_name, str) or not target_name:
            raise ValueError(f"{yml_file}: target names must be non-empty strings")
        if not isinstance(target_info, dict):
            raise ValueError(f"{yml_file}: target {target_name!r} must be a mapping")
        cores = target_info.get("cores")
        if cores is None:
            result[target_name] = None
            continue
        if (
            not isinstance(cores, list)
            or any(not isinstance(core, str) or not core for core in cores)
            or len(cores) != len(set(cores))
        ):
            raise ValueError(
                f"{yml_file}: target {target_name!r} cores must be unique "
                "non-empty strings"
            )
        # The builder's own reading, overrides included: a list published
        # another way makes the installer serve what the pack does not.
        # An empty list is a board with no core, not one with every core.
        resolved = load_target_config(
            yml_file.stem, target_name, str(targets_path.parent)
        )
        listed = None if resolved is None else sorted(resolved)
        images = target_info.get("images")
        # The image names a card's board file holds (Batocera writes
        # anbernic-rg35xx-plus for the h700 target): the installer reads
        # the board of a card prepared on a computer through them.
        result[target_name] = (
            {"cores": listed, "images": images}
            if images and listed is not None else listed
        )

    for target_name, names in alias_map.items():
        if target_name not in result:
            continue
        for alias in names:
            if alias in result:
                raise ValueError(
                    f"{yml_file}: alias {alias!r} collides with a target name"
                )
            # An alias names the board, not its images.
            held = result[target_name]
            result[alias] = held["cores"] if isinstance(held, dict) else held
    return result
