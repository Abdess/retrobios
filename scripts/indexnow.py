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
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from sitegen.indexnow import changed_urls, live_digests, payload


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
    from core.cli import run_cli

    run_cli(main)
