"""Constants shared by the audit regression suites."""

from __future__ import annotations

import tests
from pathlib import Path


try:
    import jsonschema
except ImportError:
    jsonschema = None


HAS_JSONSCHEMA = jsonschema is not None


ROOT = Path(__file__).resolve().parent.parent
