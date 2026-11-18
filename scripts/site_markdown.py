#!/usr/bin/env python3
"""Each built page as Markdown, for the assistants that read the site.

An assistant asked to help with BIOS files reads a page and answers from
it. The HTML carries navigation, icons, buttons and scripts around the
words. The Markdown copy carries the words, the tables, the commands and
the links, at `<page>/index.md` beside `<page>/index.html`. Every page's
head names it (`<link rel="alternate" type="text/markdown">`, set in
website/astro.config.mjs), and llms.txt says the convention.

`llms-full.txt` joins the Markdown of the pages a setup is done with:
the start pages, the guides and each setup's page.

An assistant often reads a copy fetched long before, by itself or by a
search engine. Each copy, llms.txt and llms-full.txt name the commit and
the date they were built from, and `version.json` names the current one,
so a stale copy can be told apart. `digests.json` gives each page's
SHA-256 before that line: the next deploy compares it with its own and
tells search engines which pages changed (scripts/indexnow.py).

Run by the Astro build once the pages are written (astro.config.mjs),
on the built site:

    python scripts/site_markdown.py website/dist
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import run_cli
from sitegen.pagemarkdown import convert_site


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("dist", type=Path, help="the built site (website/dist)")
    args = parser.parse_args()
    if not (args.dist / "index.html").is_file():
        print(f"error: {args.dist} holds no built site", file=sys.stderr)
        return 1
    count = convert_site(args.dist)
    print(f"Markdown copies: {count} pages, llms-full.txt", file=sys.stderr)
    return 0


if __name__ == "__main__":
    run_cli(main)
