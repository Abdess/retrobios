"""The headless Chromium that rasterises the committed icons and sharing cards."""

from __future__ import annotations

from typing import Any


def require_playwright() -> Any:
    """Playwright's sync_playwright, or an exit naming what to install: the
    image tools need it, the site build never does."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Playwright with Chromium is needed: pip install playwright") from exc
    return sync_playwright
