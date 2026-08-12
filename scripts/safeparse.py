"""Parsers for input the repo does not control.

Upstream DATs and scraped documents are data, never instructions, and
the parsers here are the boundary that keeps it that way."""

from __future__ import annotations

import xml.etree.ElementTree as ET

try:
    import yaml
except ImportError:  # optional at import time
    yaml = None


def parse_untrusted_xml(content: str | bytes, label: str = "XML") -> ET.Element:
    """Parse XML fetched from a third party.

    ElementTree expands internal entities, so a document that declares them
    can make the parser build a payload far larger than the bytes downloaded.
    Nothing this project reads (DAT packs, es_bios.xml, Emulators.xml) ever
    declares one, so a declaration is grounds to refuse the document rather
    than something to expand carefully.

    The check targets <!ENTITY rather than <!DOCTYPE because Logiqx DATs
    legitimately carry a doctype pointing at logiqx.com, and ElementTree does
    not resolve external entities, so a doctype alone fetches nothing.
    """
    text = content if isinstance(content, str) else content.decode("utf-8", "replace")
    if "<!ENTITY" in text.upper():
        raise ValueError(f"XML entity declarations are not allowed in {label}")
    return ET.fromstring(content)

def require_yaml():
    """Import and return yaml, exiting if PyYAML is not installed."""
    try:
        import yaml as _yaml

        return _yaml
    except ImportError:
        import sys

        print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
        sys.exit(1)

def _pick_yaml_loader():
    """Prefer the libyaml loader when the wheel ships it.

    Reading the emulator profiles is the single most expensive step of every
    command here: 375 files, and the pure-Python scanner accounts for roughly
    70% of a verify run. The C loader parses the same documents about eight
    times faster and pyyaml only exposes it when libyaml was available at
    build time, so the pure-Python class stays as the fallback.
    """
    if yaml is None:
        return None
    return getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader

_YAML_LOADER = _pick_yaml_loader()

def yaml_load(stream):
    """Parse YAML from a string or file object, safely and quickly."""
    if yaml is None:
        return require_yaml()  # exits with the install hint
    return yaml.load(stream, Loader=_YAML_LOADER)
