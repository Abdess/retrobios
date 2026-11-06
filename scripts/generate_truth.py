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
    build_target_cores_cache,
    platform_arg,
    list_registered_platforms,
    load_data_dir_registry,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    require_directory,
    require_platform,
    require_yaml,
    truth_target_dir,
    write_text_atomic,
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
        allow_abbrev=False,
        description="Generate ground-truth YAML from emulator profiles",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="all registered platforms")
    group.add_argument("--platform", "-p", type=platform_arg, help="single platform name")
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
        "--platforms-dir",
        default=DEFAULT_PLATFORMS_DIR,
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir",
        default=DEFAULT_EMULATORS_DIR,
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument("--db", default=DEFAULT_DB_FILE, help="database.json path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    require_directory(args.platforms_dir, "--platforms-dir")

    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    with open(registry_path) as f:
        registry = (yaml_load(f) or {}).get("platforms", {})

    profiles = load_emulator_profiles(args.emulators_dir)
    data_registry = load_data_dir_registry(args.platforms_dir)

    # Load database (optional)
    # The default may be absent, but a --db that was named must exist.
    db: dict | None = None
    if args.db != DEFAULT_DB_FILE or os.path.exists(args.db):
        db = load_database(args.db)

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir,
            include_archived=True,
        )
    else:
        require_platform(args.platform, args.platforms_dir)
        platforms = [args.platform]

    # A named platform without that target is refused, as verify and
    # generate_pack refuse it: skipped, it printed Done. and exited 0 with
    # no model written. --all leaves such platforms out and says so.
    target_cores_cache: dict[str, set[str] | None] = {}
    if args.target:
        try:
            target_cores_cache, platforms = build_target_cores_cache(
                platforms, args.target, args.platforms_dir, is_all=args.all
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)

    # A target-narrowed model is a different artifact: written under the
    # platform's own name it overwrote the full one, and diff_truth then
    # compared a narrowed model against the whole scrape. Its directory is
    # the target as this platform files it, as the packs are named: Lakka's
    # switch is its own image, RetroArch's is nintendo-switch.
    for name in platforms:
        output_dir = args.output_dir
        if args.target:
            output_dir = truth_target_dir(
                output_dir, [name], args.target, args.platforms_dir
            )
        os.makedirs(output_dir, exist_ok=True)
        target_cores = target_cores_cache.get(name)

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
            data_registry=data_registry,
        )

        out_path = os.path.join(output_dir, f"{name}.yml")
        # Whole or not at all: export_native and diff_truth read this file,
        # and a run stopped midway left a truncated model behind.
        write_text_atomic(
            out_path,
            yaml.dump(
                result,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            ),
        )

        n_systems = len(result.get("systems", {}))
        n_files = sum(
            len(sys_data.get("files", {}))
            for sys_data in result.get("systems", {}).values()
        )
        print(f"  {name}: {n_systems} systems, {n_files} files -> {out_path}")

    print("Done.")


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
