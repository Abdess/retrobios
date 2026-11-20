"""The buildbot system directory compared with the data directory registry, by HTTP ETag."""

from __future__ import annotations

import importlib.util
import logging
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from model.safeparse import yaml_load
from model.registry import load_versions
from .base_scraper import fetch_text


log = logging.getLogger(__name__)

BUILDBOT_SYSTEM_URL = "https://buildbot.libretro.com/assets/system/"
INDEX_URL = BUILDBOT_SYSTEM_URL + ".index"
USER_AGENT = "retrobios/1.0"
REQUEST_TIMEOUT = 15

DEFAULT_REGISTRY = "platforms/_data_dirs.yml"


def fetch_index() -> set[str]:
    """Fetch .index from buildbot, return set of ZIP filenames."""
    return {line.strip() for line in fetch_text(INDEX_URL).splitlines() if line.strip()}


def load_tracked_entries(
    registry_path: str = DEFAULT_REGISTRY,
) -> dict[str, tuple[str, str]]:
    """Load buildbot entries from _data_dirs.yml.

    Returns {decoded_zip_name: (key, source_url)}.
    """
    if importlib.util.find_spec("yaml") is None:
        print("Error: PyYAML required", file=sys.stderr)
        sys.exit(1)
    with open(registry_path) as f:
        data = yaml_load(f) or {}
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
        req = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.headers.get("ETag") or resp.headers.get("Last-Modified") or ""
    except (urllib.error.URLError, OSError):
        return None


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

    results: list[dict] = [{"zip": z, "status": "NEW", "key": None} for z in sorted(buildbot_set - tracked_set)]

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
        results.append(
            {
                "zip": z,
                "status": status,
                "key": key,
                "stored_etag": stored,
                "remote_etag": remote or "",
            }
        )

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


def update_changed(report: dict) -> list[str]:
    """Refresh entries that have changed and return the keys whose refresh failed."""
    failed: list[str] = []
    for e in report.get("entries", []):
        if e["status"] == "UPDATED" and e.get("key"):
            log.info("refreshing %s ...", e["key"])
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/refresh_data_dirs.py",
                    "--force",
                    "--key",
                    e["key"],
                ],
                check=False,
            )
            if result.returncode != 0:
                log.error("refresh of %s failed (exit %d)", e["key"], result.returncode)
                failed.append(e["key"])
    return failed


def pending(report: dict) -> list[dict]:
    """Entries a maintainer has to act on: not tracked yet, or gone."""
    return [e for e in report.get("entries", []) if e["status"] in ("NEW", "STALE")]


def unanswered(report: dict) -> list[dict]:
    """Tracked entries whose remote version could not be read."""
    return [e for e in report.get("entries", []) if e["status"] == "UNKNOWN"]
