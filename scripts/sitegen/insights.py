"""What readers look for and do not find, from totals only."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from core.artifacts import write_text_atomic
from core.github import github_token


CONFIG = Path(os.environ.get("RETROBIOS_CONFIG", Path.home() / ".config" / "retrobios"))
SITE_PROPERTY = "https://abdess.github.io/retrobios/"
GOATCOUNTER = "https://retrobios.goatcounter.com/api/v0"
REPOSITORY = "Abdess/retrobios"
SOURCES = ("gsc", "goatcounter", "github")
# Paths excluded before a window is cut in two: about 10 KB of address.
GOAT_MAX_EXCLUDED = 1000
# GoatCounter answers four requests a second and 500 per window, and says
# when to come back: a short wait is waited, a long one ends the run.
RATE_LIMIT_TRIES = 8
RATE_LIMIT_LONGEST_WAIT = 60

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


def _get_json(url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> dict | list:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers={
        "User-Agent": "retrobios-site-insights", **({"Content-Type": "application/json"} if data else {}),
        **(headers or {})})
    for _ in range(RATE_LIMIT_TRIES - 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code != 429:
                raise
            wait = int(error.headers.get("X-Rate-Limit-Reset") or 1) + 1
            if wait > RATE_LIMIT_LONGEST_WAIT:
                raise SystemExit(f"{urllib.parse.urlsplit(url).hostname} refuses requests for "
                                 f"{wait} s (rate limit); run again then, or --skip that source") from error
            time.sleep(wait)
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
        if not isinstance(answer, dict):
            raise SystemExit("Search Console answered with something other than an object")
        batch = answer.get("rows", [])
        rows += [Query(r["keys"][0], r["keys"][1], int(r["clicks"]), int(r["impressions"]),
                       float(r["position"])) for r in batch]
        if len(batch) < 25000:
            return merge_fragments(rows)


def _goat_object(url: str, auth: dict[str, str]) -> dict:
    answer = _get_json(url, auth)
    if not isinstance(answer, dict):
        raise SystemExit("GoatCounter answered with something other than an object")
    return answer


def _goat_span(start: dt.datetime, end: dt.datetime) -> dict[str, str]:
    """The hours from start up to end, end excluded: GoatCounter keeps hourly
    counts and reads an end at hh:59:59 as the last hour included."""
    last = end - dt.timedelta(seconds=1)
    return {"start": start.strftime("%Y-%m-%dT%H:00:00Z"), "end": last.strftime("%Y-%m-%dT%H:59:59Z")}


def _goat_window(start: dt.datetime, end: dt.datetime, auth: dict[str, str]) -> dict[str, int] | None:
    """Every path of one window with its count, or None once the window
    holds too many paths to page through."""
    counts: dict[str, int] = {}
    exclude: list[str] = []
    while True:
        params = urllib.parse.urlencode({**_goat_span(start, end), "limit": 100,
                                         "exclude_paths": ",".join(exclude)}, safe=",")
        answer = _goat_object(f"{GOATCOUNTER}/stats/hits?{params}", auth)
        for hit in answer.get("hits", []):
            counts[hit["path"] + (" [404]" if hit.get("title") == "404" else "")] = int(hit["count"])
            exclude.append(str(hit["path_id"]))
        if not answer.get("more"):
            return counts
        if len(exclude) >= GOAT_MAX_EXCLUDED:
            return None


def _goat_hits(start: dt.datetime, end: dt.datetime, auth: dict[str, str]) -> list[tuple[str, int]]:
    """Counts by path over the whole span, summed week by week: GoatCounter
    keeps hourly counts, so windows add up. The API pages with
    exclude_paths, which lengthens the address by every path already read,
    and the run of 2026-11-19 failed past 2,800 of them. A window with too
    many paths is read again in halves, down to one hour."""
    totals: dict[str, int] = defaultdict(int)
    week = dt.timedelta(days=7)
    pending = [(low, min(low + week, end)) for low in
               (start + n * week for n in range(-(-(end - start) // week)))]
    while pending:
        low, high = pending.pop()
        counts = _goat_window(low, high, auth)
        if counts is None:
            hours = int((high - low).total_seconds()) // 3600
            if hours <= 1:
                raise SystemExit(f"GoatCounter holds more than {GOAT_MAX_EXCLUDED} paths in the hour from {low}")
            middle = low + dt.timedelta(hours=hours // 2)
            pending += [(low, middle), (middle, high)]
            continue
        for path, count in counts.items():
            totals[path] += count
    return list(totals.items())


def fetch_goatcounter(start: dt.date, end: dt.date) -> dict:
    """Paths and events with their visit counts, and the referring domains."""
    token = (CONFIG / "goatcounter-api-token.txt").read_text(encoding="utf-8").strip()
    auth = {"Authorization": f"Bearer {token}"}
    first = dt.datetime.combine(start, dt.time(), dt.timezone.utc)
    after = dt.datetime.combine(end + dt.timedelta(days=1), dt.time(), dt.timezone.utc)
    span = _goat_span(first, after)
    hits = _goat_hits(first, after, auth)
    refs = _get_json(f"{GOATCOUNTER}/stats/toprefs?{urllib.parse.urlencode({**span, 'limit': 50})}", auth)
    total = _get_json(f"{GOATCOUNTER}/stats/total?{urllib.parse.urlencode(span)}", auth)
    if not isinstance(refs, dict) or not isinstance(total, dict):
        raise SystemExit("GoatCounter answered with something other than an object")
    # An action carries no referrer, and GoatCounter files it as a direct
    # visit: 592 of the first day's 1,145 "direct" were clicks.
    events = int(total.get("total_events", 0))
    referrers = [("(direct)", max(int(r["count"]) - events, 0)) if not r.get("name") else (r["name"], int(r["count"]))
                 for r in refs.get("stats", [])]
    return {"hits": hits, "referrers": sorted(referrers, key=lambda row: -row[1]),
            "visits": int(total.get("total", 0)) - events, "actions": events}


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
        raise SystemExit(f"{path} is not a download snapshot ({error}); move it away to start again") from error
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("counts"), dict) or "taken" not in snapshot:
        raise SystemExit(f"{path} is not a download snapshot; move it away to start again")
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
    actions = site_actions(goat["hits"])
    out = ["## On the site", "",
           f"{_span(readings.start, readings.goat_end or readings.end)}, UTC days: "
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
