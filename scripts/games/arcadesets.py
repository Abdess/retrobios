"""The published arcade documents: each game set's BIOS parent and device sets."""

from __future__ import annotations

from pathlib import Path

from games.inputs import load_json


def build_arcade(directory: Path) -> dict[str, dict]:
    if not directory.is_dir():
        return {}
    # The driver sources and the clone parents place a search path's sets at
    # build time (common.rom_search_sets): the installer reads none of them.
    return {
        path.stem: {k: v for k, v in load_json(path).items() if k not in ("sources", "parents")}
        for path in sorted(directory.glob("*.json"))
    }
