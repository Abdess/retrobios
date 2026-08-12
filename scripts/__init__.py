"""Build and verification tooling for the collection.

These modules are run as scripts (``python scripts/verify.py``), as modules
(``python -m scripts.scraper.libretro_scraper``), and imported as a package by
the tests and the type checker. The first form puts this directory on the path
itself; the other two do not, so importing the package adds it. Without that,
``import scripts.common`` fails on the first sibling import it reaches, and
every absolute import between siblings would have to be rewritten to be
relative -a change that would break running a script directly.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
