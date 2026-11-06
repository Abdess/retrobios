#!/usr/bin/env python3
"""What readers look for and do not find, from totals only.

Four sources, none of which names a person:

- Google Search Console: the searches that showed the site, by page.
- GoatCounter: page views, the domains readers came from, and the actions
  website/src/scripts/count.ts counts (searches that found nothing,
  "Did this page help?", downloads, broken links). wiki/privacy.md says
  what is sent.
- GitHub: repository traffic (14 days) and release download counts.
- The collection: which searched file names it holds, and which no
  emulator profile declares.

The report is Markdown on stdout. Credentials stay outside the repository:

    ~/.config/retrobios/gsc-service-account.json   Search Console, read only
    ~/.config/retrobios/goatcounter-api-token.txt   GoatCounter, read only
    GITHUB_TOKEN or gh auth token                   GitHub

Usage:
    python scripts/site_insights.py
    python scripts/site_insights.py --days 90 --output report.md
    python scripts/site_insights.py --skip gsc,github
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import github_token, load_database, load_emulator_profiles, run_cli

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = Path(os.environ.get("RETROBIOS_CONFIG", Path.home() / ".config" / "retrobios"))
SITE_PROPERTY = "https://abdess.github.io/retrobios/"
GOATCOUNTER = "https://retrobios.goatcounter.com/api/v0"
REPOSITORY = "Abdess/retrobios"
SOURCES = ("gsc", "goatcounter", "github")

# A word of a search that names a file: "scph5501.bin", "prod.keys".
FILE_TOKEN = re.compile(r"\b[\w.+-]+\.(?:bin|rom|zip|pup|keys|img|dat|bios|ic\d+|u\d+|sys|nvm|mec|"
                        r"rom1|j64|pce|col|sms|gb|gbc|gba|nds|cfg|chd|iso|txt|fw|dll|xml|yaml)\b", re.I)


@dataclass(frozen=True)
class Query:
    text: str
    page: str
    clicks: int
    impressions: int
    position: float

    @property
    def ctr(self) -> float:
        return self.clicks / self.impressions if self.impressions else 0.0


# Reading the sources


def _get_json(url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> dict | list:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers={
        "User-Agent": "retrobios-site-insights", **({"Content-Type": "application/json"} if data else {}),
        **(headers or {})})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _google_token(key_file: Path) -> str:
    """An access token for a service account, signed by openssl: the JWT
    grant needs RS256 and the standard library has no RSA."""
    key = json.loads(key_file.read_text(encoding="utf-8"))
    now = int(time.time())

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    claims = {"iss": key["client_email"], "scope": "https://www.googleapis.com/auth/webmasters.readonly",
              "aud": key["token_uri"], "iat": now, "exp": now + 3600}
    unsigned = f"{b64(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())}.{b64(json.dumps(claims).encode())}"
    with tempfile.TemporaryDirectory() as scratch:
        pem = Path(scratch) / "key.pem"
        pem.touch(mode=0o600)
        pem.write_text(key["private_key"], encoding="utf-8")
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(pem)],
                                   input=unsigned.encode(), capture_output=True, check=True).stdout
    body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "assertion": f"{unsigned}.{b64(signature)}"}).encode()
    request = urllib.request.Request(key["token_uri"], data=body)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)["access_token"]


def fetch_queries(start: dt.date, end: dt.date) -> list[Query]:
    token = _google_token(CONFIG / "gsc-service-account.json")
    url = ("https://www.googleapis.com/webmasters/v3/sites/"
           f"{urllib.parse.quote(SITE_PROPERTY, safe='')}/searchAnalytics/query")
    rows: list[Query] = []
    while True:
        answer = _get_json(url, {"Authorization": f"Bearer {token}"}, {
            "startDate": start.isoformat(), "endDate": end.isoformat(),
            "dimensions": ["query", "page"], "rowLimit": 25000, "startRow": len(rows)})
        batch = answer.get("rows", [])
        rows += [Query(r["keys"][0], r["keys"][1], int(r["clicks"]), int(r["impressions"]),
                       float(r["position"])) for r in batch]
        if len(batch) < 25000:
            return rows


def fetch_goatcounter(start: dt.date, end: dt.date) -> dict[str, list[tuple[str, int]]]:
    """Paths and events with their visit counts, and the referring domains."""
    token = (CONFIG / "goatcounter-api-token.txt").read_text(encoding="utf-8").strip()
    auth = {"Authorization": f"Bearer {token}"}
    span = {"start": f"{start.isoformat()}T00:00:00Z", "end": f"{end.isoformat()}T23:59:59Z"}
    hits: list[tuple[str, int]] = []
    exclude: list[str] = []
    while True:
        params = urllib.parse.urlencode({**span, "limit": 100, "exclude_paths": ",".join(exclude)})
        answer = _get_json(f"{GOATCOUNTER}/stats/hits?{params}", auth)
        for hit in answer.get("hits", []):
            hits.append((hit["path"] + (" [404]" if hit.get("title") == "404" else ""), int(hit["count"])))
            exclude.append(str(hit["path_id"]))
        if not answer.get("more"):
            break
    refs = _get_json(f"{GOATCOUNTER}/stats/toprefs?{urllib.parse.urlencode({**span, 'limit': 50})}", auth)
    referrers = [(r.get("name") or "(direct)", int(r["count"])) for r in refs.get("stats", [])]
    return {"hits": hits, "referrers": referrers}


def fetch_github() -> dict:
    token = github_token()
    if not token:
        raise SystemExit("GitHub traffic needs a token: GITHUB_TOKEN, or gh auth login")
    auth = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    api = f"https://api.github.com/repos/{REPOSITORY}"
    releases = _get_json(f"{api}/releases?per_page=10", auth)
    return {
        "views": _get_json(f"{api}/traffic/views", auth),
        "clones": _get_json(f"{api}/traffic/clones", auth),
        "referrers": _get_json(f"{api}/traffic/popular/referrers", auth),
        "paths": _get_json(f"{api}/traffic/popular/paths", auth),
        "downloads": [(release["tag_name"], asset["name"], asset["download_count"])
                      for release in releases for asset in release.get("assets", [])],
    }


# Reading the figures


def searched_files(queries: list[Query], held: set[str], declared: set[str]) -> list[tuple[str, int, str]]:
    """File names typed in searches, by impressions, with what the project
    knows of each: held in the collection, declared by a profile only, or
    unknown."""
    seen: dict[str, int] = defaultdict(int)
    shown: dict[str, str] = {}
    for query in queries:
        for token in FILE_TOKEN.findall(query.text):
            key = token.casefold()
            seen[key] += query.impressions
            shown.setdefault(key, token)
    state = {key: "held" if key in held else "declared, not held" if key in declared else "unknown"
             for key in seen}
    return sorted(((shown[key], seen[key], state[key]) for key in seen), key=lambda row: -row[1])


def missed_clicks(queries: list[Query], least: int = 100) -> list[Query]:
    """On the first page but rarely clicked: what the result says loses
    the reader."""
    return sorted((q for q in queries if q.position <= 10 and q.impressions >= least and q.ctr < 0.03),
                  key=lambda q: -q.impressions)


def near_first_page(queries: list[Query], least: int = 50) -> list[Query]:
    return sorted((q for q in queries if 10 < q.position <= 20 and q.impressions >= least),
                  key=lambda q: -q.impressions)


def site_actions(hits: list[tuple[str, int]]) -> dict[str, list[tuple[str, int]]]:
    """Events by kind ("search-none", "helpful", "download"...), pages apart."""
    groups: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for path, count in hits:
        if path.endswith(" [404]"):
            groups["404"].append((path.removesuffix(" [404]"), count))
        elif not path.startswith("/") and "/" in path:
            kind, _, name = path.partition("/")
            groups[kind].append((name, count))
        else:
            groups["pages"].append((path, count))
    return {kind: sorted(rows, key=lambda row: -row[1]) for kind, rows in groups.items()}


# The report


def _table(header: tuple[str, ...], rows: list[tuple], limit: int = 25) -> list[str]:
    if not rows:
        return ["None.", ""]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows[:limit]]
    return [*lines, ""]


def _page(url: str) -> str:
    return url.removeprefix(SITE_PROPERTY.rstrip("/")) or "/"


def report(start: dt.date, end: dt.date, queries: list[Query] | None, goat: dict | None,
           github: dict | None, held: set[str], declared: set[str]) -> str:
    out = [f"# Site insights, {start.isoformat()} to {end.isoformat()}", ""]
    if queries is not None:
        clicks = sum(q.clicks for q in queries)
        shown = sum(q.impressions for q in queries)
        out += ["## Google searches", "",
                f"{clicks:,} clicks, {shown:,} impressions, {len({q.text for q in queries}):,} searches.", "",
                "### On the first page, rarely clicked", "",
                *_table(("Search", "Page", "Impressions", "CTR", "Position"),
                        [(q.text, _page(q.page), f"{q.impressions:,}", f"{q.ctr:.1%}", f"{q.position:.1f}")
                         for q in missed_clicks(queries)]),
                "### Just past the first page", "",
                *_table(("Search", "Page", "Impressions", "Position"),
                        [(q.text, _page(q.page), f"{q.impressions:,}", f"{q.position:.1f}")
                         for q in near_first_page(queries)]),
                "### File names searched", "",
                *_table(("File", "Impressions", "In the project"),
                        [(f"`{name}`", f"{seen:,}", state)
                         for name, seen, state in searched_files(queries, held, declared)], limit=40)]
    if goat is not None:
        actions = site_actions(goat["hits"])
        named = {"search-none": "Site searches that found nothing", "404": "Broken addresses",
                 "helpful": "Did this page help?", "get": "Pack pages opened",
                 "download": "Release downloads", "file": "File downloads", "copy": "Copy buttons",
                 "out": "Links leaving the site", "pages": "Pages"}
        out += ["## On the site", ""]
        for kind, title in named.items():
            if kind in actions:
                out += [f"### {title}", "", *_table(("Name", "Visits"), [(n, f"{c:,}") for n, c in actions[kind]])]
        out += ["### Came from", "", *_table(("Site", "Visits"), [(n, f"{c:,}") for n, c in goat["referrers"]])]
    if github is not None:
        views, clones = github["views"], github["clones"]
        out += ["## GitHub", "",
                f"Last 14 days: {views.get('count', 0):,} views by {views.get('uniques', 0):,} visitors, "
                f"{clones.get('count', 0):,} clones.", "",
                "### Came from", "",
                *_table(("Site", "Views", "Visitors"),
                        [(r["referrer"], r["count"], r["uniques"]) for r in github["referrers"]]),
                "### Most viewed", "",
                *_table(("Path", "Views"), [(p["path"], p["count"]) for p in github["paths"]]),
                "### Release downloads", "",
                *_table(("Release", "File", "Downloads"),
                        sorted(github["downloads"], key=lambda row: -row[2]), limit=40)]
    return "\n".join(out).rstrip() + "\n"


def collection_names(db: dict, profiles: dict[str, dict]) -> tuple[set[str], set[str]]:
    """File names the collection holds, and those a profile declares."""
    held = {name.casefold() for name in db.get("indexes", {}).get("by_name", {})}
    declared: set[str] = set()
    for profile in profiles.values():
        for entry in profile.get("files") or []:
            if isinstance(entry, dict):
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if name:
                        declared.add(Path(str(name)).name.casefold())
    return held, declared


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--days", type=int, default=28, help="days to read, ending 3 days ago (default 28)")
    parser.add_argument("--skip", default="", help=f"sources to leave out, among {', '.join(SOURCES)}")
    parser.add_argument("--output", type=Path, help="write the report here instead of stdout")
    args = parser.parse_args()
    skip = {name.strip() for name in args.skip.split(",") if name.strip()}
    unknown = skip - set(SOURCES)
    if unknown:
        parser.error(f"unknown source(s): {', '.join(sorted(unknown))}")
    # Search Console data settles two to three days after the fact.
    end = dt.date.today() - dt.timedelta(days=3)
    start = end - dt.timedelta(days=args.days - 1)
    held, declared = collection_names(load_database(str(REPO_ROOT / "database.json")),
                                      load_emulator_profiles(str(REPO_ROOT / "emulators")))
    queries = None if "gsc" in skip else fetch_queries(start, end)
    goat = None if "goatcounter" in skip else fetch_goatcounter(start, dt.date.today())
    github = None if "github" in skip else fetch_github()
    text = report(start, end, queries, goat, github, held, declared)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    run_cli(main)
