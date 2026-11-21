"""What a verify run hands a program: its JSON entries and the pack destinations file."""

from __future__ import annotations

import json
from pathlib import Path

from packs.report import pack_shares
from packs.verdicts import Severity, Status


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
    """What each platform's pack holds according to the report, as JSON.

    Keyed by registry id: the name verify prints, its OK and total counts,
    the core files and game data the pack takes from the cores, and the
    paths it credits. The pipeline's consistency check reads them here
    rather than from the printed report.
    """
    destinations = {}
    for (result, names), (group, _rep) in zip(group_results, groups):
        core_files, game_data = pack_shares(result)
        for name, key in zip(names, group):
            destinations[key] = {
                "platform": key,
                "label": name,
                "ok": result["severity_counts"][Severity.OK],
                "total": result["total_files"],
                "core_files": core_files + game_data,
                "pack_destinations": result["pack_destinations"],
            }
    Path(path).write_text(json.dumps(destinations, indent=1, sort_keys=True))
