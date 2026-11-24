"""Readers of upstream sources, each written to a file of this repository.

The `<name>_scraper.py` modules at this level each read one platform's BIOS
list into `platforms/<platform>.yml`: the registry's `scraper:` field names
the module, and `freshness.scrapers.platform_scraper` turns it into the
command that runs it. base_scraper.py holds what they share, the network
access included. The subpackages hold the other subjects: `targets/` the
cores each hardware target ships, `romfolders/` each setup's rom folders,
`launchers/` what each platform's launch code reads and passes to a core,
`arcade/` the MAME and FBNeo hashes and romset recipes, and `dats/` the dump
catalogs read from DAT files.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Scrapers run both as `python -m scripts.scraper.<module>` and as plain
# scripts, and they share helpers with the rest of scripts/. Putting that
# directory on the path once here is what lets every submodule say
# `from core.cli import ...` instead of carrying its own bootstrap.
if (_SCRIPTS_DIR := str(Path(__file__).resolve().parent.parent)) not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
