"""The site's fixed names and addresses, and the date its data is read at."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from core.paths import REPO_ROOT
from model import releaserecord
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
                  releaserecord.GET_DIR]
# Generated directories of files served as they are, not pages.
PUBLIC_DIRS = ("api", "downloads")


def build_commit(root: Path = REPO_ROOT) -> str:
    """The commit the site is built from: GITHUB_SHA in CI, HEAD locally.

    Anything but a full commit id raises: the installer address and the
    page stamps name it, and a branch name there would move under them.
    """
    commit = os.environ.get("GITHUB_SHA", "").strip()
    if not commit:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"not a commit id: {commit!r}")
    return commit


def data_as_of(moment: datetime | None = None) -> str:
    """The build date for a reader, in words, with the machine form beside it.
    A raw ISO stamp ("2026-10-22T22:43:08Z") closed the home page."""
    moment = moment or datetime.now(timezone.utc)
    return (f'<time datetime="{moment.strftime("%Y-%m-%dT%H:%M:%SZ")}">'
            f"Data as of {moment.day} {moment.strftime('%B %Y')}</time>")


def date_line() -> str:
    """The date a page closes on, in the words of data_as_of(). The search
    does not read it: a query word such as the "2" of "playstation 2 bios"
    also matches the start of "2026", and every page closing on the date
    then held every word of the query."""
    return f'<div class="rb-timestamp" data-pagefind-ignore>{data_as_of()}.</div>'
