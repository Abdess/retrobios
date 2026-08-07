#!/usr/bin/env python3
"""Check emulator profile source_refs against the profiled upstream.

Resolves the upstream commit in effect at each profile's profiled_date
(or uses source_commit when the profile carries one), fetches every file
a source_ref points to at that commit and at HEAD, and reports whether
the values the profile declares still sit where the ref says.

A ref is checked by looking for the entry's declared hashes (or filename
when no hash exists) in a window around the cited lines. Three outcomes
per ref at each revision: anchored (found in the window), moved (found
elsewhere in the file), gone (absent from the file).

Usage:
    python scripts/check_profile_refs.py --emulator vice
    python scripts/check_profile_refs.py --all
    python scripts/check_profile_refs.py --emulator clk --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from common import load_emulator_profiles

WINDOW = 40
RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
API_COMMITS = (
    "https://api.github.com/repos/{owner}/{repo}/commits"
    "?until={date}T23:59:59Z&per_page=1"
)

_GITHUB_RE = re.compile(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
_REF_RE = re.compile(r"^(?P<path>[^:]+?)(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?$")

_file_cache: dict[tuple[str, str, str, str], list[str] | None] = {}


def parse_source_ref(ref: str) -> tuple[str, int | None, int | None]:
    """Split 'path/file.cpp:123-129' into (path, start, end)."""
    m = _REF_RE.match(ref.strip())
    if not m:
        return ref.strip(), None, None
    start = int(m.group("start")) if m.group("start") else None
    end = int(m.group("end")) if m.group("end") else start
    return m.group("path"), start, end


def collect_tokens(entry: dict) -> list[str]:
    """Declared values worth searching for near the ref: hashes, then name."""
    tokens: list[str] = []
    for field in ("sha1", "md5", "crc32", "sha256", "known_hash_adler32"):
        val = entry.get(field)
        vals = val if isinstance(val, list) else [val] if val else []
        for v in vals:
            v = str(v).lower().removeprefix("0x")
            if v:
                tokens.append(v)
    if not tokens:
        name = entry.get("name", "")
        if name:
            tokens.append(os.path.basename(name).lower())
    return tokens


def match_ref(
    lines: list[str] | None,
    start: int | None,
    end: int | None,
    tokens: list[str],
) -> str:
    """Return anchored / moved / gone for one ref against one revision."""
    if lines is None:
        return "gone"
    text = [ln.lower() for ln in lines]
    if start is not None:
        lo = max(0, start - 1 - WINDOW)
        hi = min(len(text), (end or start) + WINDOW)
        window = text[lo:hi]
        if any(tok in ln for tok in tokens for ln in window):
            return "anchored"
    if any(tok in ln for tok in tokens for ln in text):
        return "moved" if start is not None else "anchored"
    return "gone"


def _github_repo(url: str) -> tuple[str, str] | None:
    m = _GITHUB_RE.match(url.strip())
    return (m.group(1), m.group(2)) if m else None


def _http_json(url: str) -> object:
    headers = {"User-Agent": "retrobios-refcheck/1.0"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def resolve_commit_at(owner: str, repo: str, date: str) -> str | None:
    """Last default-branch commit on or before the given date."""
    url = API_COMMITS.format(owner=owner, repo=repo, date=date)
    try:
        data = _http_json(url)
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        print(f"  {owner}/{repo}: commit lookup failed: {exc}", file=sys.stderr)
        return None
    if isinstance(data, list) and data:
        return data[0].get("sha")
    return None


def fetch_lines(owner: str, repo: str, ref: str, path: str) -> list[str] | None:
    key = (owner, repo, ref, path)
    if key in _file_cache:
        return _file_cache[key]
    url = RAW_URL.format(
        owner=owner, repo=repo, ref=ref, path=urllib.parse.quote(path)
    )
    headers = {"User-Agent": "retrobios-refcheck/1.0"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            lines = resp.read().decode("utf-8", errors="replace").splitlines()
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            print(f"  fetch {url}: HTTP {exc.code}", file=sys.stderr)
        lines = None
    except urllib.error.URLError as exc:
        print(f"  fetch {url}: {exc}", file=sys.stderr)
        lines = None
    _file_cache[key] = lines
    return lines


def check_profile(name: str, profile: dict) -> dict:
    """Check every source_ref of one profile. Returns a report dict."""
    report: dict = {
        "profile": name,
        "repos": [],
        "pinned_commit": None,
        "commit_source": None,
        "refs": [],
        "skipped": None,
    }

    repos = []
    for field in ("upstream", "source"):
        url = profile.get(field, "")
        gh = _github_repo(url) if url else None
        if gh and gh not in repos:
            repos.append(gh)
    if not repos:
        report["skipped"] = "no github repository in upstream/source"
        return report
    report["repos"] = [f"{o}/{r}" for o, r in repos]

    pinned = profile.get("source_commit")
    if pinned:
        report["commit_source"] = "source_commit"
    else:
        date = str(profile.get("profiled_date", ""))
        if not date:
            report["skipped"] = "no source_commit and no profiled_date"
            return report
        for owner, repo in repos:
            pinned = resolve_commit_at(owner, repo, date)
            if pinned:
                repos = [(owner, repo)] + [r for r in repos if r != (owner, repo)]
                break
        report["commit_source"] = f"resolved from profiled_date {date}"
    if not pinned:
        report["skipped"] = "commit resolution failed"
        return report
    report["pinned_commit"] = pinned

    rank = {"gone": 0, "moved": 1, "anchored": 2}
    for entry in profile.get("files", []):
        ref = entry.get("source_ref", "")
        if not ref:
            continue
        tokens = collect_tokens(entry)

        # A source_ref may carry several comma-separated references;
        # the entry holds as long as one of them does.
        pin_status = "gone"
        head_status = "gone"
        for part in (p.strip() for p in ref.split(",") if p.strip()):
            path, start, end = parse_source_ref(part)
            for owner, repo in repos:
                pin_lines = fetch_lines(owner, repo, pinned, path)
                if pin_lines is None and (owner, repo) != repos[-1]:
                    continue
                head_lines = fetch_lines(owner, repo, "HEAD", path)
                pin_part = match_ref(pin_lines, start, end, tokens)
                head_part = match_ref(head_lines, start, end, tokens)
                if rank[pin_part] > rank[pin_status]:
                    pin_status = pin_part
                if rank[head_part] > rank[head_status]:
                    head_status = head_part
                break

        report["refs"].append({
            "name": entry.get("name", ""),
            "source_ref": ref,
            "at_pin": pin_status,
            "at_head": head_status,
        })
    return report


def _print_report(report: dict) -> None:
    name = report["profile"]
    if report["skipped"]:
        print(f"{name}: skipped ({report['skipped']})")
        return
    refs = report["refs"]
    pin = report["pinned_commit"][:12]
    print(f"{name}: {len(refs)} refs against {pin} ({report['commit_source']})")
    for state, where in (("at_pin", "pin"), ("at_head", "HEAD")):
        counts: dict[str, int] = {}
        for r in refs:
            counts[r[state]] = counts.get(r[state], 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        print(f"  at {where}: {summary}")
    for r in refs:
        if r["at_pin"] != "anchored" or r["at_head"] != "anchored":
            print(
                f"  {r['source_ref']} ({r['name']}): "
                f"pin={r['at_pin']} HEAD={r['at_head']}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check profile source_refs against upstream revisions"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emulator", help="check a single profile")
    group.add_argument("--all", action="store_true", help="check every profile")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    if args.emulator:
        if args.emulator not in profiles:
            print(f"unknown profile: {args.emulator}", file=sys.stderr)
            sys.exit(1)
        selected = {args.emulator: profiles[args.emulator]}
    else:
        selected = {
            k: v
            for k, v in sorted(profiles.items())
            if v.get("type") not in ("alias", "test")
        }

    reports = [check_profile(name, prof) for name, prof in selected.items()]
    if args.as_json:
        print(json.dumps(reports, indent=2))
    else:
        for report in reports:
            _print_report(report)


if __name__ == "__main__":
    main()
