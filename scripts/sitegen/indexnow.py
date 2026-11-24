"""The pages a deploy changes, as the request body IndexNow takes."""

from __future__ import annotations

import json

from core import forgehttp
from sitegen.agents import INDEXNOW_FILE, INDEXNOW_KEY, PUBLISHER, SITE

HOST = PUBLISHER
# What one IndexNow request accepts.
MAX_URLS = 10_000
USER_AGENT = "retrobios-indexnow"


def live_digests(url: str = f"{SITE}digests.json") -> dict[str, str]:
    """The digests the live site serves. None yet (the first deploy that
    writes them) is an empty map: every page is new."""
    body = forgehttp.fetch_body(url, timeout=60, user_agent=USER_AGENT)
    return {} if body is None else json.loads(body.decode("utf-8"))


def changed_urls(new: dict[str, str], old: dict[str, str]) -> list[str]:
    """Pages added, changed or removed between two digest maps."""
    return sorted(url for url in new.keys() | old.keys() if new.get(url) != old.get(url))


def payload(urls: list[str]) -> dict:
    if len(urls) > MAX_URLS:
        raise SystemExit(f"error: {len(urls)} changed pages, one request takes {MAX_URLS}")
    return {"host": HOST, "key": INDEXNOW_KEY, "keyLocation": f"{SITE}{INDEXNOW_FILE}",
            "urlList": urls}
