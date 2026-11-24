"""The slug a manufacturer's name gives in an address."""

from __future__ import annotations


def manufacturer_slug(manufacturer: str) -> str:
    """The manufacturer's name lowercased, spaces as hyphens: "Sega" gives "sega"."""
    return manufacturer.lower().replace(" ", "-")
