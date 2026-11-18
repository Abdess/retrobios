"""Parsers for input the repo does not control.

Upstream DATs and scraped documents are data, never instructions, and
the parsers here are the boundary that keeps it that way."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from types import ModuleType
from typing import Any, TextIO

try:
    import yaml
except ImportError:  # optional at import time
    yaml = None


def parse_untrusted_xml(
    content: str | bytes, label: str = "XML", comments: bool = False
) -> ET.Element:
    """Parse XML fetched from a third party.

    ElementTree expands internal entities, so a document that declares them
    can make the parser build a payload far larger than the bytes downloaded.
    Nothing this project reads (DAT packs, es_bios.xml, Emulators.xml) ever
    declares one, so a declaration is grounds to refuse the document rather
    than something to expand carefully.

    The check targets <!ENTITY rather than <!DOCTYPE because Logiqx DATs
    legitimately carry a doctype pointing at logiqx.com, and ElementTree does
    not resolve external entities, so a doctype alone fetches nothing.
    `comments` keeps comments in the tree, for a file rewritten in place.
    """
    text = content if isinstance(content, str) else content.decode("utf-8", "replace")
    if "<!ENTITY" in text.upper():
        raise ValueError(f"XML entity declarations are not allowed in {label}")
    if comments:
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        return ET.fromstring(content, parser=parser)
    return ET.fromstring(content)

def require_yaml() -> ModuleType:
    """Import and return yaml, exiting if PyYAML is not installed."""
    try:
        import yaml as _yaml

        return _yaml
    except ImportError:
        import sys

        print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
        sys.exit(1)

def _pick_yaml_loader() -> type[yaml.constructor.SafeConstructor] | None:
    """Prefer the libyaml loader when the wheel ships it.

    Reading the emulator profiles is the single most expensive step of every
    command here: 375 files, and the pure-Python scanner accounts for roughly
    70% of a verify run. The C loader parses the same documents about eight
    times faster and pyyaml only exposes it when libyaml was available at
    build time, so the pure-Python class stays as the fallback.
    """
    if yaml is None:
        return None
    base = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader

    def construct_mapping(
        self: yaml.constructor.SafeConstructor, node: yaml.MappingNode, deep: bool = False
    ) -> dict:
        """Refuse a mapping that names a key twice.

        PyYAML keeps the last value without a word: the registry once
        carried two target_source keys for Recalbox and read only one. Only
        a mapping that came out shorter than its source is re-read. No data
        here uses merge keys (<<), which would count as repeats too.
        """
        mapping = base.construct_mapping(self, node, deep=deep)
        if len(mapping) < len(node.value):
            seen: set = set()
            for key_node, _value in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        None, None, f"duplicate key {key!r}", key_node.start_mark
                    )
                seen.add(key)
        return mapping

    return type("_UniqueKeyLoader", (base,), {"construct_mapping": construct_mapping})

_YAML_LOADER = _pick_yaml_loader()

def yaml_load(stream: str | TextIO) -> Any:
    """Parse YAML from a string or file object, safely and quickly."""
    if yaml is None:
        return require_yaml()  # exits with the install hint
    return yaml.load(stream, Loader=_YAML_LOADER)


def yaml_load_upstream(stream: str | TextIO) -> Any:
    """Parse a third party's YAML the way its own PyYAML code reads it.

    Our files refuse a repeated key, but a platform's file is data we transcribe,
    and its code keeps the last value. Batocera 43.1's configgen-defaults.yml
    names rtcw's core twice, and refusing it stopped the rescrape.
    """
    if yaml is None:
        return require_yaml()
    return yaml.load(stream, Loader=getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader)
