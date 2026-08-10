#!/usr/bin/env python3
"""Generate ground-truth YAML files per platform from emulator profiles.

Usage:
    python scripts/generate_truth.py --platform retroarch --output-dir dist/truth
    python scripts/generate_truth.py --all --output-dir dist/truth
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    load_target_config,
    require_yaml,
    yaml_load,
)
from truth import generate_platform_truth

yaml = require_yaml()

DEFAULT_OUTPUT_DIR = "dist/truth"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_EMULATORS_DIR = "emulators"
DEFAULT_DB_FILE = "database.json"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ground-truth YAML from emulator profiles",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="all registered platforms")
    group.add_argument("--platform", help="single platform name")
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="output directory",
    )
    parser.add_argument(
        "--target",
        "-t",
        default=None,
        help="hardware target filter",
    )
    parser.add_argument(
        "--include-archived",
        action="store_true",
        help="include archived platforms with --all",
    )
    parser.add_argument(
        "--platforms-dir",
        default=DEFAULT_PLATFORMS_DIR,
    )
    parser.add_argument(
        "--emulators-dir",
        default=DEFAULT_EMULATORS_DIR,
    )
    parser.add_argument("--db", default=DEFAULT_DB_FILE, help="database.json path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # Load registry
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    with open(registry_path) as f:
        registry = (yaml_load(f) or {}).get("platforms", {})

    # Load emulator profiles
    profiles = load_emulator_profiles(args.emulators_dir)

    # Load database (optional)
    db: dict | None = None
    if os.path.exists(args.db):
        db = load_database(args.db)

    # Determine platforms
    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir,
            include_archived=args.include_archived,
        )
    else:
        platforms = [args.platform]

    os.makedirs(args.output_dir, exist_ok=True)

    for name in platforms:
        # Resolve target cores
        target_cores: set[str] | None = None
        if args.target:
            try:
                target_cores = load_target_config(
                    name,
                    args.target,
                    args.platforms_dir,
                )
            except FileNotFoundError:
                print(f"  {name}: no target config, skipped")
                continue

        # Load platform config (with inheritance) and registry entry
        try:
            config = load_platform_config(name, args.platforms_dir)
        except FileNotFoundError:
            print(f"  {name}: no platform config, skipped")
            continue
        registry_entry = registry.get(name, {})

        result = generate_platform_truth(
            name,
            config,
            registry_entry,
            profiles,
            db=db,
            target_cores=target_cores,
        )

        out_path = os.path.join(args.output_dir, f"{name}.yml")
        with open(out_path, "w") as f:
            yaml.dump(
                result,
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

        n_systems = len(result.get("systems", {}))
        n_files = sum(
            len(sys_data.get("files", {}))
            for sys_data in result.get("systems", {}).values()
        )
        print(f"  {name}: {n_systems} systems, {n_files} files -> {out_path}")

    print("Done.")


if __name__ == "__main__":
    main()
