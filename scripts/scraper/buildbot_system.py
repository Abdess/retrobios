"""The buildbot system directory compared with the data directory registry, by HTTP ETag."""

from __future__ import annotations

import logging
import urllib.error
import urllib.parse

from core.upstream import remote_etag as get_remote_etag
from core.paths import DATA_DIRS_FILE
from model.registry import data_dir_registry_at, load_versions
from .base_scraper import fetch_text


log = logging.getLogger(__name__)

BUILDBOT_SYSTEM_URL = "https://buildbot.libretro.com/assets/system/"
INDEX_URL = BUILDBOT_SYSTEM_URL + ".index"



def fetch_index() -> set[str]:
    """Fetch .index from buildbot, return set of ZIP filenames."""
    return {line.strip() for line in fetch_text(INDEX_URL).splitlines() if line.strip()}


def load_tracked_entries(
    registry_path: str = DATA_DIRS_FILE,
) -> dict[str, tuple[str, str]]:
    """Load buildbot entries from _data_dirs.yml.

    Returns {decoded_zip_name: (key, source_url)}.
    """
    entries: dict[str, tuple[str, str]] = {}
    for key, entry in data_dir_registry_at(registry_path, required=True).items():
        url = entry.get("source_url", "")
        if "buildbot.libretro.com/assets/system" not in url:
            continue
        zip_name = urllib.parse.unquote(url.rsplit("/", 1)[-1])
        entries[zip_name] = (key, url)
    return entries


def check(registry_path: str = DATA_DIRS_FILE) -> dict:
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


def updated(report: dict) -> list[str]:
    """Keys of the tracked entries whose remote version changed."""
    return [e["key"] for e in report.get("entries", []) if e["status"] == "UPDATED" and e.get("key")]


def pending(report: dict) -> list[dict]:
    """Entries a maintainer has to act on: not tracked yet, or gone."""
    return [e for e in report.get("entries", []) if e["status"] in ("NEW", "STALE")]


def unanswered(report: dict) -> list[dict]:
    """Tracked entries whose remote version could not be read."""
    return [e for e in report.get("entries", []) if e["status"] == "UNKNOWN"]
