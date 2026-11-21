"""What a verify run hands a program: its JSON entries and the pack destinations file."""

from __future__ import annotations

import json
from pathlib import Path

from packs.verdicts import Status


def json_details(details: list[dict], verbose: bool) -> list[dict]:
    """The entries a JSON report lists: what needs attention, or every one.

    --verbose shows each entry with its ground truth in the text report. It
    used to be accepted beside --json and dropped, the output byte for byte
    the same, so a script asking for the passing entries got nothing.
    """
    return list(details) if verbose else [
        d for d in details if d["status"] != Status.OK or d.get("release_asset")
    ]


def write_pack_destinations(
    path: str,
    groups: list[tuple[list[str], str]],
    group_results: list[tuple[dict, list[str]]],
) -> None:
    """The paths each pack holds according to the report, per platform, as JSON."""
    destinations = {}
    for (result, names), (group, _rep) in zip(group_results, groups):
        for name, key in zip(names, group):
            destinations[name] = {
                "platform": key, "pack_destinations": result["pack_destinations"],
            }
    Path(path).write_text(json.dumps(destinations, indent=1, sort_keys=True))
