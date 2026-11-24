"""Fixture inputs for the README renderer, so a test reads the text it writes."""

from __future__ import annotations

import dataclasses

from sitegen.readme import ReadmeInputs

# One setup a release carries a pack for, one served by the command alone.
RELEASED_SIZE = 16011 * 1024 * 1024
RECORD = {
    "packs": {
        "RetroArch_BIOS_Pack.zip": {
            "platforms": ["retroarch"],
            "files": 4525,
            "extracted_size": RELEASED_SIZE,
        },
    },
}


def readme_inputs(**changes: object) -> ReadmeInputs:
    """A small, offline set of inputs, with *changes* applied."""
    inputs = ReadmeInputs(
        total_files=19526,
        coverages={
            "retroarch": {"platform": "RetroArch"},
            "recalbox": {"platform": "Recalbox"},
        },
        profiles={
            "core": {"files": [{"name": "a.bin", "source_ref": "src/a.c:120"}]},
            "closed": {"upstream": "closed source", "files": [{"name": "b.bin"}]},
        },
        record=RECORD,
        extract_paths={"RetroArch": "`system`"},
        archive_counts={"total": 3, "exact": 2, "canonical": 1},
        clone="Packs are built from a clone.",
        contributors=[],
        kept_contributors=[],
        generated_at="2026-01-01T00:00:00Z",
    )
    return dataclasses.replace(inputs, **changes)  # type: ignore[arg-type]
