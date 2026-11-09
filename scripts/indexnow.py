#!/usr/bin/env python3
"""The pages a deploy changes, as the IndexNow list a search engine takes.

A search engine revisits a page on its own schedule, and an assistant that
searches through it reads the copy it last saw. IndexNow (Bing, Yandex,
Seznam, Naver) takes a list of changed addresses and fetches them soon
after. Google does not take it and reads the sitemap.

The built site carries `digests.json`, each page's SHA-256 before its build
line (scripts/site_markdown.py). This compares it with the one the live site
serves, before the deploy replaces it: a page whose digest differs, a new
page and a removed one are listed. The deploy job posts the list once the
new site is live (.github/workflows/deploy-site.yml).

    python scripts/indexnow.py --dist website/dist              # print the list
    python scripts/indexnow.py --dist website/dist --output "$GITHUB_OUTPUT"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from siteagents import INDEXNOW_FILE, INDEXNOW_KEY, SITE  # noqa: E402

HOST = "abdess.github.io"
# What one IndexNow request accepts.
MAX_URLS = 10_000
USER_AGENT = "retrobios-indexnow"


def live_digests(url: str = f"{SITE}digests.json") -> dict[str, str]:
    """The digests the live site serves. None yet (the first deploy that
    writes them) is an empty map: every page is new."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        raise


def changed_urls(new: dict[str, str], old: dict[str, str]) -> list[str]:
    """Pages added, changed or removed between two digest maps."""
    return sorted(url for url in new.keys() | old.keys() if new.get(url) != old.get(url))


def payload(urls: list[str]) -> dict:
    if len(urls) > MAX_URLS:
        raise SystemExit(f"error: {len(urls)} changed pages, one request takes {MAX_URLS}")
    return {"host": HOST, "key": INDEXNOW_KEY, "keyLocation": f"{SITE}{INDEXNOW_FILE}",
            "urlList": urls}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--dist", type=Path, required=True, help="the built site (website/dist)")
    parser.add_argument("--output", type=Path,
                        help="append payload=<json> to this file (a GitHub step output)")
    args = parser.parse_args()
    new = json.loads((args.dist / "digests.json").read_text(encoding="utf-8"))
    urls = changed_urls(new, live_digests())
    print(f"{len(urls)} of {len(new)} pages changed", file=sys.stderr)
    if not urls:
        return 0
    body = json.dumps(payload(urls), separators=(",", ":"))
    if args.output:
        with args.output.open("a", encoding="utf-8") as handle:
            handle.write(f"payload={body}\n")
    else:
        print(body)
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
