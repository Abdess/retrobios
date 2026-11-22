"""What readers look for and do not find, from totals only."""

from __future__ import annotations

import base64
import datetime as dt
import io
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from core import upstream
from core.artifacts import write_text_atomic
from core.cli import SourceUnreadable
from core.github import github_token
from sitegen.config import REPO_SLUG, SITE_URL


CONFIG = Path(os.environ.get("RETROBIOS_CONFIG", Path.home() / ".config" / "retrobios"))
SITE_PROPERTY = SITE_URL
GOATCOUNTER = "https://retrobios.goatcounter.com/api/v0"
REPOSITORY = REPO_SLUG
SOURCES = ("gsc", "goatcounter", "github")
USER_AGENT = "retrobios-site-insights"
# GoatCounter builds an export in the background: it is asked for every
# EXPORT_POLL seconds, EXPORT_TRIES times. It allows one export an hour.
EXPORT_POLL = 5
EXPORT_TRIES = 60
# GoatCounter answers four requests a second and 500 per window, and says
# when to come back in X-Rate-Limit-Reset. core.upstream.open_retrying waits
# a short wait and gives up on a long one, which ends the run.

# Expected click-through rate: the site's own rate at each rounded
# position, positions past 20 pooled in LAST_BUCKET. A bucket under
# BUCKET_FLOOR impressions borrows its neighbours. A search on the first
# page is rarely clicked below MISSED_SHARE of its bucket's rate.
LAST_BUCKET = 21
BUCKET_FLOOR = 500
MISSED_SHARE = 0.5
FILE_ROWS = 40

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


class SourceUnavailable(Exception):
    """A source that could not be read this run, and how long until it answers again.

    The command leaves the source out of the report and says why, instead of
    losing what the other sources already gave.
    """

    def __init__(self, reason: str, wait: float | None = None) -> None:
        super().__init__(reason)
        self.wait = wait


def _open(request: urllib.request.Request) -> tuple[int, bytes]:
    """Status and body of a request, retried by core.upstream.open_retrying:
    a dropped connection or a 5xx is asked again, a rate limit waited out."""
    try:
        return upstream.open_retrying(request, lambda response: (response.status, response.read()), 60)
    except (urllib.error.HTTPError, upstream.RateLimitError) as error:
        if isinstance(error, urllib.error.HTTPError) and error.code != 429:
            raise
        headers = error.headers if isinstance(error, urllib.error.HTTPError) else None
        wait = upstream.requested_wait(headers)
        delay = f" for {wait:.0f} s" if wait is not None else ""
        raise SourceUnavailable(f"{urllib.parse.urlsplit(request.full_url).hostname} refuses requests"
                                f"{delay} (rate limit); run again then", wait) from error


def _fetch(url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    return _open(urllib.request.Request(url, data=data, headers={
        "User-Agent": USER_AGENT, **({"Content-Type": "application/json"} if data else {}),
        **(headers or {})}))


def _get_json(url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> dict | list:
    return json.loads(_fetch(url, headers, body)[1])


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
    request = urllib.request.Request(key["token_uri"], data=body, headers={"User-Agent": USER_AGENT})
    return json.loads(_open(request)[1])["access_token"]


def _credential(path: Path, source: str) -> Path:
    """A credential file of the configuration folder, or the source is unavailable."""
    if not path.is_file():
        raise SourceUnavailable(f"{source} needs {path}")
    return path


def fetch_queries(start: dt.date, end: dt.date) -> list[Query]:
    token = _google_token(_credential(CONFIG / "gsc-service-account.json", "Search Console"))
    url = ("https://www.googleapis.com/webmasters/v3/sites/"
           f"{urllib.parse.quote(SITE_PROPERTY, safe='')}/searchAnalytics/query")
    rows: list[Query] = []
    while True:
        answer = _get_json(url, {"Authorization": f"Bearer {token}"}, {
            "startDate": start.isoformat(), "endDate": end.isoformat(),
            "dimensions": ["query", "page"], "rowLimit": 25000, "startRow": len(rows)})
        if not isinstance(answer, dict):
            raise SourceUnavailable("Search Console answered with something other than an object")
        batch = answer.get("rows", [])
        rows += [Query(r["keys"][0], r["keys"][1], int(r["clicks"]), int(r["impressions"]),
                       float(r["position"])) for r in batch]
        if len(batch) < 25000:
            return merge_fragments(rows)


def _goat_export(first: dt.datetime, auth: dict[str, str]) -> bytes:
    """The site's JSON export from the day of first: a ZIP of hourly counts.
    Reading the same counts from /stats/hits pages by excluding the paths
    already read, and four weeks took more than the 500 requests GoatCounter
    allows in an hour. The export takes three or four."""
    export = _get_json(f"{GOATCOUNTER}/export", auth,
                       {"format": "json", "start_from_day": first.strftime("%Y-%m-%dT00:00:00Z")})
    if not isinstance(export, dict) or "id" not in export:
        raise SourceUnavailable("GoatCounter did not start an export")
    for _ in range(EXPORT_TRIES):
        time.sleep(EXPORT_POLL)
        status, raw = _fetch(f"{GOATCOUNTER}/export/{export['id']}/download", auth)
        if status == 200:
            return raw
    raise SourceUnavailable(f"GoatCounter export {export['id']} not ready after {EXPORT_POLL * EXPORT_TRIES} s")


def read_export(raw: bytes, first: dt.datetime, after: dt.datetime) -> dict:
    """Paths and events with their counts, the referring domains of page
    views, from first up to after (excluded), and the first day counted.
    An action is counted as a path without a leading slash and carries no
    referrer."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = {Path(name).name: name for name in archive.namelist()}

        def rows(name: str) -> list[dict]:
            return [json.loads(line) for line in archive.read(members[name]).decode().splitlines() if line]

        paths = {row["id"]: row["path"] + (" [404]" if row.get("title") == "404" else "")
                 for row in rows("paths.jsonl")}
        refs = {row["id"]: row["ref"] for row in rows("refs.jsonl")}
        stats = rows("hit_stats.jsonl")
    low, high = first.strftime("%Y-%m-%dT%H:00:00Z"), after.strftime("%Y-%m-%dT%H:00:00Z")
    hits: dict[str, int] = defaultdict(int)
    referrers: dict[str, int] = defaultdict(int)
    hours: set[str] = set()
    for row in stats:
        if low <= row["hour"] < high:
            hours.add(row["hour"])
            path = paths[row["path_id"]]
            hits[path] += row["count"]
            if path.startswith("/"):
                referrers[refs[row["ref_id"]] or "(direct)"] += row["count"]
    actions = sum(count for path, count in hits.items() if not path.startswith("/"))
    return {"hits": list(hits.items()), "referrers": sorted(referrers.items(), key=lambda row: -row[1]),
            "visits": sum(hits.values()) - actions, "actions": actions,
            "first_day": dt.date.fromisoformat(min(hours)[:10]) if hours else None}


def fetch_goatcounter(start: dt.date, end: dt.date) -> dict:
    """Paths and events with their visit counts, and the referring domains."""
    token = _credential(CONFIG / "goatcounter-api-token.txt", "GoatCounter").read_text(encoding="utf-8").strip()
    first = dt.datetime.combine(start, dt.time(), dt.timezone.utc)
    after = dt.datetime.combine(end + dt.timedelta(days=1), dt.time(), dt.timezone.utc)
    return read_export(_goat_export(first, {"Authorization": f"Bearer {token}"}), first, after)


def fetch_github() -> dict:
    # Traffic figures are only served to the owner: without a token there
    # is nothing to read, not a smaller quota.
    if not github_token():
        raise SourceUnavailable("GitHub traffic needs a token: GITHUB_TOKEN, or gh auth login")
    api = f"https://api.github.com/repos/{REPOSITORY}"
    auth = upstream.forge_headers(api, "application/vnd.github+json", USER_AGENT)
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


def merge_fragments(queries: list[Query]) -> list[Query]:
    """One row per search and page: Search Console reports /page/#anchor
    apart from /page/, so the same search appears once per anchor."""
    groups: dict[tuple[str, str], list[Query]] = defaultdict(list)
    for query in queries:
        groups[(query.text, query.page.partition("#")[0])].append(query)
    return [_combined(text, page, rows) for (text, page), rows in groups.items()]


def _combined(text: str, page: str, rows: list[Query]) -> Query:
    """Clicks and impressions add up, the position is weighted by impressions."""
    shown = sum(q.impressions for q in rows)
    position = (sum(q.position * q.impressions for q in rows) / shown if shown
                else sum(q.position for q in rows) / len(rows))
    return Query(text, page, sum(q.clicks for q in rows), shown, position)


def _bucket(position: float) -> int:
    return min(max(1, int(position + 0.5)), LAST_BUCKET)


def expected_ctr(queries: list[Query]) -> dict[int, float]:
    """The site's own click-through rate at each rounded position: clicks
    over impressions of every search in the bucket, positions past 20 in
    one bucket. A bucket under BUCKET_FLOOR impressions is pooled with its
    neighbours, one on each side at a time, until the window holds that many."""
    clicks = [0] * (LAST_BUCKET + 1)
    shown = [0] * (LAST_BUCKET + 1)
    for query in queries:
        clicks[_bucket(query.position)] += query.clicks
        shown[_bucket(query.position)] += query.impressions
    expected: dict[int, float] = {}
    for bucket in range(1, LAST_BUCKET + 1):
        for reach in range(LAST_BUCKET):
            window = range(max(1, bucket - reach), min(LAST_BUCKET, bucket + reach) + 1)
            seen = sum(shown[i] for i in window)
            if seen >= BUCKET_FLOOR:
                break
        expected[bucket] = sum(clicks[i] for i in window) / seen if seen else 0.0
    return expected


def _expected_clicks(expected: dict[int, float], query: Query) -> float:
    return expected.get(_bucket(query.position), 0.0) * query.impressions


def missed_clicks(queries: list[Query], expected: dict[int, float], least: int = 100) -> list[Query]:
    """On the first page, shown at least `least` times, and clicked less
    than MISSED_SHARE of what the site gets at that position: what the
    result says loses the reader. Most clicks lost first."""
    return sorted((q for q in queries if q.position <= 10 and q.impressions >= least
                   and q.ctr < MISSED_SHARE * expected.get(_bucket(q.position), 0.0)),
                  key=lambda q: (q.clicks - _expected_clicks(expected, q), q.text))


def near_first_page(queries: list[Query], least: int = 50) -> list[Query]:
    return sorted((q for q in queries if 10 < q.position <= 20 and q.impressions >= least),
                  key=lambda q: -q.impressions)


@dataclass(frozen=True)
class PageReading:
    page: str
    clicks: int
    impressions: int
    position: float
    lost: float
    top: tuple[str, ...]

    @property
    def ctr(self) -> float:
        return self.clicks / self.impressions if self.impressions else 0.0


def by_page(queries: list[Query], expected: dict[int, float]) -> list[PageReading]:
    """Searches summed by page, the page that loses the most clicks against
    the site's own rate at each position first. `lost` is expected minus
    actual clicks, negative when the page does better than its positions."""
    groups: dict[str, list[Query]] = defaultdict(list)
    for query in queries:
        groups[query.page].append(query)
    readings = []
    for page, rows in groups.items():
        total = _combined("", page, rows)
        top = tuple(q.text for q in sorted(rows, key=lambda q: (-q.impressions, q.text))[:3])
        readings.append(PageReading(page, total.clicks, total.impressions, total.position,
                                    sum(_expected_clicks(expected, q) - q.clicks for q in rows), top))
    return sorted(readings, key=lambda r: (-r.lost, r.page))


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


# Release download counts are all-time counters: a snapshot of the last
# run's counts gives the change between two runs.


def downloads_snapshot(downloads: list[tuple[str, str, int]], taken: dt.datetime) -> dict:
    return {"taken": taken.strftime("%Y-%m-%d %H:%M UTC"),
            "counts": {f"{tag}/{name}": count for tag, name, count in downloads}}


def load_snapshot(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SourceUnreadable(f"{path} is not a download snapshot ({error}); move it away to start again") from error
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("counts"), dict) or "taken" not in snapshot:
        raise SourceUnreadable(f"{path} is not a download snapshot; move it away to start again")
    return snapshot


def save_snapshot(path: Path, snapshot: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(str(path), json.dumps(snapshot, indent=2, sort_keys=True) + "\n")


def download_rows(downloads: list[tuple[str, str, int]], snapshot: dict | None) -> list[tuple]:
    """(release, file, change, all time) by change, or (release, file, all
    time) by count without a snapshot. A file the snapshot lacks is new."""
    if snapshot is None:
        return [(tag, name, f"{count:,}") for tag, name, count in sorted(downloads, key=lambda row: -row[2])]
    before = snapshot["counts"]
    rows = [(tag, name, count - int(before.get(f"{tag}/{name}", 0)), count, f"{tag}/{name}" not in before)
            for tag, name, count in downloads]
    rows.sort(key=lambda row: (-row[2], -row[3]))
    return [(tag, name, f"{change:+,}" + (" (new)" if new else ""), f"{count:,}")
            for tag, name, change, count, new in rows]


# The report


@dataclass(frozen=True)
class Readings:
    """What one run read. A source left out is None."""
    start: dt.date
    end: dt.date
    now: dt.datetime
    held: set[str]
    declared: set[str]
    queries: list[Query] | None = None
    previous: list[Query] | None = None
    goat: dict | None = None
    goat_end: dt.date | None = None
    github: dict | None = None
    snapshot: dict | None = None
    # Each source that could not be read, with why: "GitHub: ... needs a token".
    left_out: tuple[str, ...] = ()

    @property
    def previous_span(self) -> tuple[dt.date, dt.date]:
        """The period of the same length just before."""
        last = self.start - dt.timedelta(days=1)
        return last - (self.end - self.start), last


def _table(header: tuple[str, ...], rows: list[tuple], limit: int = 25) -> list[str]:
    if not rows:
        return ["None.", ""]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows[:limit]]
    return [*lines, ""]


def _page(url: str) -> str:
    return url.removeprefix(SITE_PROPERTY.rstrip("/")) or "/"


def _span(start: dt.date, end: dt.date) -> str:
    return f"{start.isoformat()} to {end.isoformat()} ({(end - start).days + 1} days)"


def _google_totals(readings: Readings, queries: list[Query]) -> str:
    clicks = sum(q.clicks for q in queries)
    shown = sum(q.impressions for q in queries)
    line = (f"{_span(readings.start, readings.end)}: {clicks:,} clicks, {shown:,} impressions, "
            f"{len({q.text for q in queries}):,} searches.")
    if readings.previous is None:
        return line
    first, last = readings.previous_span
    if not readings.previous:
        return f"{line} Search Console holds nothing for the period before, {_span(first, last)}."
    before_clicks = sum(q.clicks for q in readings.previous)
    before_shown = sum(q.impressions for q in readings.previous)
    return (f"{line} Against {_span(first, last)}: {clicks - before_clicks:+,} clicks, "
            f"{shown - before_shown:+,} impressions.")


def _change(now: PageReading, then: PageReading | None, field: str, compared: bool) -> str:
    """A figure, and its change against the period before when there is one."""
    value = getattr(now, field)
    shown = f"{value:.1f}" if field == "position" else f"{value:,}"
    if not compared:
        return shown
    if then is None:
        return f"{shown} (new)"
    diff = value - getattr(then, field)
    return f"{shown} ({diff:+.1f})" if field == "position" else f"{shown} ({diff:+,})"


def _page_rows(readings: Readings, pages: list[PageReading]) -> list[tuple]:
    before = {r.page: r for r in by_page(readings.previous or [], {})}
    compared = bool(before)
    return [(_page(r.page), f"{r.lost:,.0f}", _change(r, before.get(r.page), "clicks", compared),
             _change(r, before.get(r.page), "impressions", compared), f"{r.ctr:.1%}",
             _change(r, before.get(r.page), "position", compared), "; ".join(r.top))
            for r in pages]


def _file_names(queries: list[Query], held: set[str], declared: set[str]) -> list[str]:
    rows = searched_files(queries, held, declared)
    missing = [(f"`{name}`", f"{seen:,}", state) for name, seen, state in rows if state != "held"]
    if not rows:
        return ["No search named a file.", ""]
    if not missing:
        return [f"All {len(rows):,} searched file names are held.", ""]
    shown = "" if len(missing) <= FILE_ROWS else f", the {FILE_ROWS} most searched"
    return [f"{len(rows) - len(missing):,} of {len(rows):,} searched file names are held. "
            f"Not held ({len(missing):,}{shown}):", "",
            *_table(("File", "Impressions", "In the project"), missing, limit=FILE_ROWS)]


def _google(readings: Readings, queries: list[Query]) -> list[str]:
    expected = expected_ctr(queries)
    return ["## Google searches", "", _google_totals(readings, queries), "",
            "### By page", "",
            "Lost clicks: what the page's searches would get at the site's own click rate for each "
            "position, minus what they got. Changes are against the period before.", "",
            *_table(("Page", "Lost clicks", "Clicks", "Impressions", "CTR", "Position", "Top searches"),
                    _page_rows(readings, by_page(queries, expected)), limit=30),
            "### On the first page, rarely clicked", "",
            f"Clicked less than half the site's rate at that position, {_span(readings.start, readings.end)}.", "",
            *_table(("Search", "Page", "Impressions", "CTR", "Expected CTR", "Position"),
                    [(q.text, _page(q.page), f"{q.impressions:,}", f"{q.ctr:.1%}",
                      f"{expected.get(_bucket(q.position), 0.0):.1%}", f"{q.position:.1f}")
                     for q in missed_clicks(queries, expected)]),
            "### Just past the first page", "",
            *_table(("Search", "Page", "Impressions", "Position"),
                    [(q.text, _page(q.page), f"{q.impressions:,}", f"{q.position:.1f}")
                     for q in near_first_page(queries)]),
            "### File names searched", "",
            *_file_names(queries, readings.held, readings.declared)]


SITE_ACTIONS = {"search-none": "Site searches that found nothing", "404": "Broken addresses",
                "helpful": "Did this page help?", "get": "Pack pages opened",
                "download": "Release downloads", "file": "File downloads", "copy": "Copy buttons",
                "out": "Links leaving the site", "pages": "Pages"}


def _goatcounter(readings: Readings, goat: dict) -> list[str]:
    # The site counts visits since 2026-11-06: a period that starts
    # earlier is stated from the first day GoatCounter holds.
    actions = site_actions(goat["hits"])
    start = max(readings.start, goat.get("first_day") or readings.start)
    out = ["## On the site", "",
           f"{_span(start, readings.goat_end or readings.end)}, UTC days: "
           f"{goat.get('visits', 0):,} page views, {goat.get('actions', 0):,} actions.", ""]
    for kind, title in SITE_ACTIONS.items():
        if kind in actions:
            out += [f"### {title}", "", *_table(("Name", "Visits"), [(n, f"{c:,}") for n, c in actions[kind]])]
    return [*out, "### Came from", "", *_table(("Site", "Visits"), [(n, f"{c:,}") for n, c in goat["referrers"]])]


def _github(readings: Readings, github: dict) -> list[str]:
    views, clones = github["views"], github["clones"]
    days = [day["timestamp"][:10] for day in views.get("views", [])]
    span = f"{days[0]} to {days[-1]}" if days else "the last 14 days"
    snapshot = readings.snapshot
    if snapshot is None:
        downloads = ("All-time counters. No earlier snapshot: this run writes the first, "
                     "the next run shows the change since.")
        header: tuple[str, ...] = ("Release", "File", "Downloads, all time")
    else:
        downloads = f"Change since the snapshot of {snapshot['taken']}, and the all-time counters."
        header = ("Release", "File", f"Since {snapshot['taken']}", "All time")
    return ["## GitHub", "",
            f"Traffic as the API keeps it, 14 days ({span}): {views.get('count', 0):,} views by "
            f"{views.get('uniques', 0):,} visitors, {clones.get('count', 0):,} clones.", "",
            "### Came from", "",
            *_table(("Site", "Views", "Visitors"),
                    [(r["referrer"], f"{r['count']:,}", f"{r['uniques']:,}") for r in github["referrers"]]),
            "### Most viewed", "",
            *_table(("Path", "Views"), [(p["path"], f"{p['count']:,}") for p in github["paths"]]),
            "### Release downloads", "", downloads, "",
            *_table(header, download_rows(github["downloads"], snapshot), limit=40)]


def report(readings: Readings) -> str:
    out = ["# Site insights", "", f"Written {readings.now.strftime('%Y-%m-%d %H:%M UTC')}. "
           "Each section gives its own period.", ""]
    if readings.left_out:
        out += ["Not read this run:", "", *(f"- {line}" for line in readings.left_out), ""]
    if readings.queries is not None:
        out += _google(readings, readings.queries)
    if readings.goat is not None:
        out += _goatcounter(readings, readings.goat)
    if readings.github is not None:
        out += _github(readings, readings.github)
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
