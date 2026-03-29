#!/usr/bin/env python3
"""Check buildbot system directory for changes against local registry.

Compares the live buildbot assets/system/.index against _data_dirs.yml
entries using HTTP ETag headers for change detection.

Usage:
    python scripts/check_buildbot_system.py
    python scripts/check_buildbot_system.py --update
    python scripts/check_buildbot_system.py --json
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

BUILDBOT_SYSTEM_URL = "https://buildbot.libretro.com/assets/system/"
INDEX_URL = BUILDBOT_SYSTEM_URL + ".index"
USER_AGENT = "retrobios/1.0"
REQUEST_TIMEOUT = 15

DEFAULT_REGISTRY = "platforms/_data_dirs.yml"
VERSIONS_FILE = "data/.versions.json"


def fetch_index() -> set[str]:
    """Fetch .index from buildbot, return set of ZIP filenames."""
    req = urllib.request.Request(INDEX_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return {line.strip() for line in resp.read().decode().splitlines() if line.strip()}


def load_tracked_entries(registry_path: str = DEFAULT_REGISTRY) -> dict[str, tuple[str, str]]:
    """Load buildbot entries from _data_dirs.yml.

    Returns {decoded_zip_name: (key, source_url)}.
    """
    try:
        import yaml
    except ImportError:
        print("Error: PyYAML required", file=sys.stderr)
        sys.exit(1)
    with open(registry_path) as f:
        data = yaml.safe_load(f) or {}
    entries: dict[str, tuple[str, str]] = {}
    for key, entry in data.get("data_directories", {}).items():
        url = entry.get("source_url", "")
        if "buildbot.libretro.com/assets/system" not in url:
            continue
        zip_name = urllib.parse.unquote(url.rsplit("/", 1)[-1])
        entries[zip_name] = (key, url)
    return entries


def get_remote_etag(url: str) -> str | None:
    """HEAD request to get ETag."""
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.headers.get("ETag") or resp.headers.get("Last-Modified") or ""
    except (urllib.error.URLError, OSError):
        return None


def load_versions(versions_path: str = VERSIONS_FILE) -> dict:
    """Load cached version/ETag data."""
    path = Path(versions_path)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def check(registry_path: str = DEFAULT_REGISTRY) -> dict:
    """Run the buildbot check. Returns structured report."""
    try:
        index_zips = fetch_index()
    except (urllib.error.URLError, OSError) as exc:
        log.warning("buildbot unreachable: %s", exc)
        return {"error": str(exc), "entries": []}

    tracked = load_tracked_entries(registry_path)
    versions = load_versions()

    buildbot_set = set(index_zips)
    tracked_set = set(tracked.keys())

    results: list[dict] = []

    for z in sorted(buildbot_set - tracked_set):
        results.append({"zip": z, "status": "NEW", "key": None})

    for z in sorted(tracked_set - buildbot_set):
        key, _ = tracked[z]
        results.append({"zip": z, "status": "STALE", "key": key})

    for z in sorted(tracked_set & buildbot_set):
        key, url = tracked[z]
        stored = versions.get(key, {}).get("sha", "")
        remote = get_remote_etag(url)
        if remote is None:
            status = "UNKNOWN"
        elif remote == stored:
            status = "OK"
        else:
            status = "UPDATED"
        results.append({"zip": z, "status": status, "key": key,
                        "stored_etag": stored, "remote_etag": remote or ""})

    return {"entries": results}


def print_report(report: dict) -> None:
    """Print human-readable report."""
    if report.get("error"):
        print(f"WARNING: {report['error']}")
        return
    entries = report["entries"]
    print(f"Buildbot system check ({len(entries)} entries):")
    for e in entries:
        pad = 40 - len(e["zip"])
        dots = "." * max(pad, 2)
        print(f"  {e['zip']} {dots} {e['status']}")
    counts: dict[str, int] = {}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    parts = [f"{v} {k.lower()}" for k, v in sorted(counts.items())]
    print(f"\nSummary: {', '.join(parts)}")


def update_changed(report: dict) -> None:
    """Refresh entries that have changed."""
    for e in report.get("entries", []):
        if e["status"] == "UPDATED" and e.get("key"):
            log.info("refreshing %s ...", e["key"])
            subprocess.run(
                [sys.executable, "scripts/refresh_data_dirs.py",
                 "--force", "--key", e["key"]],
                check=False,
            )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(
        description="Check buildbot system directory for changes",
    )
    parser.add_argument("--update", action="store_true",
                        help="Auto-refresh changed entries")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Machine-readable JSON output")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    args = parser.parse_args()

    report = check(args.registry)

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    if args.update:
        update_changed(report)


if __name__ == "__main__":
    main()
