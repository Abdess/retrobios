"""The site's fixed names and addresses, and the date its data is read at."""

from __future__ import annotations

from datetime import datetime, timezone

import release_record
from core.paths import REPO_ROOT
from model.safeparse import require_yaml


yaml = require_yaml()

# The Starlight project, and where its pages go inside it.
STARLIGHT_DIR = "website"
STARLIGHT_CONTENT = "src/content/docs"
SITE_NAME = "RetroBIOS"
REPO_URL = "https://github.com/Abdess/retrobios"
RELEASE_URL = f"{REPO_URL}/releases/latest"
# What LICENSE grants over the published data: its MIT terms name the
# metadata. The BIOS files themselves are under NOTICE, never this.
DATA_LICENSE = "MIT (LICENSE: scripts, tooling, schemas, documentation and metadata)"
SITE_URL = "https://abdess.github.io/retrobios/"
GENERATED_DIRS = ["platforms", "systems", "emulators", "wiki", "api", "downloads", "files",
                  release_record.GET_DIR]
# Generated directories of files served as they are, not pages.
PUBLIC_DIRS = ("api", "downloads")


def _timestamp() -> str:
    """The build time for data files (stats, API records), ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def data_as_of(moment: datetime | None = None) -> str:
    """The build date for a reader, in words, with the machine form beside it.
    A raw ISO stamp ("2026-10-22T22:43:08Z") closed the home page."""
    moment = moment or datetime.now(timezone.utc)
    return (f'<time datetime="{moment.strftime("%Y-%m-%dT%H:%M:%SZ")}">'
            f"Data as of {moment.day} {moment.strftime('%B %Y')}</time>")


def _date_line() -> str:
    """The date a page closes on, in the words of data_as_of(). The search
    does not read it: a query word such as the "2" of "playstation 2 bios"
    also matches the start of "2026", and every page closing on the date
    then held every word of the query."""
    return f'<div class="rb-timestamp" data-pagefind-ignore>{data_as_of()}.</div>'


_REPO_ROOT = REPO_ROOT
