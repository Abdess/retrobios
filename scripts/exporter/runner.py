"""Exporting, or refreshing the cached originals of, each selected platform in turn."""

from __future__ import annotations

from pathlib import Path

from exporter import discover_exporters
from exporter.native import export_platform, refresh_cache
from model.registry import load_platform_registry


def run(
    platforms: list[str],
    truth_dir: str,
    output_dir: str,
    platforms_dir: str,
    upstream_dir: str,
    allow_fetch: bool,
    refresh_only: bool = False,
) -> int:
    """Export each platform, or refresh its cached original: 1 when any failed or has no exporter."""
    exporters = discover_exporters()
    registry = load_platform_registry(platforms_dir)
    failures = 0
    skipped: list[str] = []

    for platform in sorted(platforms):
        exporter_class = exporters.get(platform)
        if not exporter_class and (registry.get(platform) or {}).get("native_list") == "none":
            # The platform's code names no BIOS file: there is no list of its
            # own to hand back corrected.
            print(f"  SKIP {platform}: names no BIOS file of its own (native_list: none)")
            continue
        if not exporter_class:
            skipped.append(platform)
            print(f"  SKIP {platform}: no exporter")
            continue

        if refresh_only:
            ok, messages = refresh_cache(
                platform,
                exporter_class,
                Path(truth_dir),
                platforms_dir,
                Path(upstream_dir),
            )
        else:
            ok, messages = export_platform(
                platform,
                exporter_class,
                Path(truth_dir),
                Path(output_dir),
                platforms_dir,
                Path(upstream_dir),
                allow_fetch,
            )
        label = "OK  " if ok else "FAIL"
        print(f"  {label} {platform}")
        for message in messages:
            print(f"       {message}")
        if not ok:
            failures += 1

    if skipped:
        print(f"\n{len(skipped)} platform(s) without an exporter: {', '.join(skipped)}")
        failures += len(skipped)

    return 1 if failures else 0
