"""Export truth data to native platform formats."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml

from common import list_registered_platforms, load_platform_config
from exporter import discover_exporters


OUTPUT_FILENAMES: dict[str, str] = {
    "retroarch": "System.dat",
    "batocera": "batocera-systems",
    "recalbox": "es_bios.xml",
    "retrobat": "batocera-systems.json",
}


def output_filename(platform: str) -> str:
    """Return the native output filename for a platform."""
    return OUTPUT_FILENAMES.get(platform, f"{platform}_bios.dat")


def run(
    platforms: list[str],
    truth_dir: str,
    output_dir: str,
    platforms_dir: str,
) -> int:
    """Export truth to native formats, return exit code."""
    exporters = discover_exporters()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    errors = 0

    for platform in sorted(platforms):
        exporter_cls = exporters.get(platform)
        if not exporter_cls:
            print(f"  SKIP {platform}: no exporter available")
            continue

        truth_file = Path(truth_dir) / f"{platform}.yml"
        if not truth_file.exists():
            print(f"  SKIP {platform}: {truth_file} not found")
            continue

        with open(truth_file) as f:
            truth_data = yaml.safe_load(f) or {}

        scraped: dict | None = None
        try:
            scraped = load_platform_config(platform, platforms_dir)
        except (FileNotFoundError, OSError):
            pass

        dest = str(output_path / output_filename(platform))
        exporter = exporter_cls()
        exporter.export(truth_data, dest, scraped_data=scraped)

        issues = exporter.validate(truth_data, dest)
        if issues:
            print(f"  WARN {platform}: {len(issues)} validation issue(s)")
            for issue in issues:
                print(f"       {issue}")
            errors += 1
        else:
            print(f"  OK   {platform} -> {dest}")

    return 1 if errors else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export truth data to native platform formats.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="export all platforms")
    group.add_argument("--platform", help="export a single platform")
    parser.add_argument(
        "--output-dir", default="dist/upstream", help="output directory",
    )
    parser.add_argument(
        "--truth-dir", default="dist/truth", help="truth YAML directory",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms", help="platform configs directory",
    )
    parser.add_argument(
        "--include-archived", action="store_true",
        help="include archived platforms",
    )
    args = parser.parse_args()

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir, include_archived=args.include_archived,
        )
    else:
        platforms = [args.platform]

    code = run(platforms, args.truth_dir, args.output_dir, args.platforms_dir)
    sys.exit(code)


if __name__ == "__main__":
    main()
