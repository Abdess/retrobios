#!/usr/bin/env python3
"""Rewrite each platform's own BIOS file, corrected by the ground truth.

The output is the file the platform maintains, not a rendering of our data
in its syntax: what the truth can prove is applied, what it says nothing
about is left alone, and what it knows and the platform lacks is added. The
formats that carry code are patched rather than regenerated, so the checker
a platform ships keeps working.

Usage:
    python scripts/export_native.py --all --fetch
    python scripts/export_native.py --platform recalbox --upstream-dir up/
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import list_registered_platforms, load_platform_config, yaml_load
from exporter import discover_exporters
from exporter.baseline import build_native_model

DEFAULT_CACHE = ".cache/upstream-native"
_USER_AGENT = "retrobios-exporter/1.0"
_MAX_BYTES = 64 * 1024 * 1024


def fetch(url: str, destination: Path) -> bytes:
    """Download an original once, then read it from the cache."""
    if destination.exists():
        return destination.read_bytes()
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(_MAX_BYTES + 1)
    if len(payload) > _MAX_BYTES:
        raise ValueError(f"{url}: response larger than {_MAX_BYTES} bytes")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return payload


def pinned_base(wanted: dict[str, str], scraped: dict | None) -> str:
    """The revision our transcription came from, when the YAML records it.

    A scraper pins a stable tag (batocera-43.1, BizHawk 2.11.1) and writes
    that URL into the platform YAML. Patching the branch tip instead would
    correct a file our data never described.
    """
    source = _raw_url(str((scraped or {}).get("source", "")))
    for relative in wanted:
        if source.endswith("/" + relative):
            return source[: -len(relative)]
    return ""


def _raw_url(url: str) -> str:
    """A GitHub blob page names a revision but serves HTML; raw serves bytes."""
    marker = "/blob/"
    if url.startswith("https://github.com/") and marker in url:
        owner_repo, _, path = url[len("https://github.com/") :].partition(marker)
        return f"https://raw.githubusercontent.com/{owner_repo}/{path}"
    return url


def collect_originals(
    exporter: object,
    systems: dict,
    upstream_dir: Path,
    allow_fetch: bool,
    scraped: dict | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Gather the platform's own files, from disk or from upstream."""
    wanted = dict(exporter.native_sources())
    components = getattr(exporter, "components", None)
    if callable(components):
        for component in components(systems):
            wanted[f"{component}/component_manifest.json"] = exporter.component_url(
                component
            )

    base = pinned_base(wanted, scraped)
    if base:
        wanted = {relative: base + relative for relative in wanted}

    root = upstream_dir / exporter.platform_name()
    originals: dict[str, str] = {}
    missing: list[str] = []
    for relative, url in wanted.items():
        path = root / relative
        payload: bytes | None = None
        if path.exists():
            payload = path.read_bytes()
        elif allow_fetch:
            try:
                payload = fetch(url, path)
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
                missing.append(f"{relative}: {exc}")
                continue
        else:
            missing.append(f"{relative}: absent and fetching is off")
            continue

        unpack = getattr(exporter, "unpack", None)
        if callable(unpack) and relative.endswith((".zip", ".tar.gz")):
            originals.update(unpack(payload))
        else:
            originals[relative] = payload.decode("utf-8", errors="replace")

    return originals, missing


def export_platform(
    platform: str,
    exporter_class: type,
    truth_dir: Path,
    output_dir: Path,
    platforms_dir: str,
    upstream_dir: Path,
    allow_fetch: bool,
) -> tuple[bool, list[str]]:
    """Write one platform's corrected file. Returns (ok, messages)."""
    messages: list[str] = []

    truth_file = truth_dir / f"{platform}.yml"
    truth: dict = {}
    if truth_file.exists():
        with open(truth_file) as handle:
            truth = yaml_load(handle) or {}
    else:
        messages.append(f"no truth for {platform}, only the platform's own data")

    try:
        scraped = load_platform_config(platform, platforms_dir)
    except (FileNotFoundError, OSError):
        scraped = None

    systems, report = build_native_model(truth, scraped)
    if not systems:
        return False, ["nothing to write: neither the platform nor the truth has data"]

    exporter = exporter_class()
    originals, missing = collect_originals(
        exporter, systems, upstream_dir, allow_fetch, scraped
    )
    if missing and exporter.needs_original():
        return False, [f"the platform's own file is required: {m}" for m in missing]
    messages.extend(
        f"original unavailable, written from our data: {m}" for m in missing
    )

    try:
        produced = exporter.render(systems, report, originals, scraped)
    except ValueError as exc:
        return False, [str(exc)]

    if not produced and not exporter.may_write_nothing():
        return False, ["the exporter produced no file"]

    issues = exporter.validate(systems, produced)

    platform_dir = output_dir / platform
    for relative, content in produced.items():
        path = platform_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    # Only what the format can state: a correction to a field the file has
    # no place for is not a change the maintainer will find in the diff, and
    # counting it would announce work the export did not do.
    carried = exporter.carries()
    applied = [
        correction
        for correction in report.hashes_corrected
        if correction.rsplit(" ", 1)[-1] in carried
    ]
    requirements = len(report.required_corrected) if "required" in carried else 0

    landed = 0
    refused = 0
    lost = 0
    for system in systems.values():
        for entry in system.files:
            if not entry.name:
                continue
            if exporter.writable(entry):
                landed += entry.platform is None
            elif entry.platform is None:
                refused += 1
            else:
                # The platform declares it and the format still cannot state
                # it, so their own file loses a line. Worth saying out loud.
                lost += 1

    summary = exporter.outcome(systems, produced)
    if summary is None:
        summary = (
            f"{report.files_kept} kept, {landed} added, "
            f"{len(applied)} hashes corrected, {requirements} requirements corrected"
        )
        if refused:
            summary += f", {refused} the format cannot state"
        if lost:
            summary += f", {lost} of theirs dropped"
    messages.append(summary)
    for correction in applied[:5]:
        messages.append(f"hash corrected: {correction}")
    if len(applied) > 5:
        messages.append(f"and {len(applied) - 5} more hash corrections")

    messages.extend(f"INVALID: {issue}" for issue in issues[:10])
    if len(issues) > 10:
        messages.append(f"and {len(issues) - 10} more validation failures")

    return not issues, messages


def run(
    platforms: list[str],
    truth_dir: str,
    output_dir: str,
    platforms_dir: str,
    upstream_dir: str,
    allow_fetch: bool,
) -> int:
    exporters = discover_exporters()
    failures = 0
    skipped: list[str] = []

    for platform in sorted(platforms):
        exporter_class = exporters.get(platform)
        if not exporter_class:
            skipped.append(platform)
            print(f"  SKIP {platform}: no exporter")
            continue

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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rewrite each platform's own BIOS file, corrected.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="every platform")
    group.add_argument("--platform", help="a single platform")
    parser.add_argument("--output-dir", default="dist/upstream")
    parser.add_argument("--truth-dir", default="dist/truth")
    parser.add_argument("--platforms-dir", default="platforms")
    parser.add_argument(
        "--upstream-dir",
        default=DEFAULT_CACHE,
        help="where the platforms' own files are read and cached",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="download a platform's file when it is not in the cache",
    )
    args = parser.parse_args()

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir,
            include_archived=True,
        )
    else:
        platforms = [args.platform]

    sys.exit(
        run(
            platforms,
            args.truth_dir,
            args.output_dir,
            args.platforms_dir,
            args.upstream_dir,
            args.fetch,
        )
    )


if __name__ == "__main__":
    main()
