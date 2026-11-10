#!/usr/bin/env python3
"""Write schemas/install-events.schema.json from install.py's EVENT_KEYS.

    python scripts/generate_event_schema.py           rewrite the schema
    python scripts/generate_event_schema.py --check   exit 1 when it is stale
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from artifacts import write_text_atomic

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "schemas" / "install-events.schema.json"

_spec = importlib.util.spec_from_file_location("install", ROOT / "install.py")
_install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_install)

EVENT_KEYS: dict[str, tuple[str, ...]] = _install.EVENT_KEYS
EVENT_SCHEMA: int = _install.EVENT_SCHEMA

_TEXT = {"type": "string"}
_COUNT = {"type": "integer", "minimum": 0}
_FLAG = {"type": "boolean"}
_NAMES = {"type": "array", "items": {"type": "string"}}
_RECORDS = {"type": "array", "items": {"type": "object"}}

# The JSON type of each key, whatever kind carries it. A key EVENT_KEYS
# gains without a line here stops the generator.
KEY_TYPES: dict[str, dict] = {
    **dict.fromkeys((
        "installer", "os", "os_name", "stage", "reason", "platform", "message",
        "folder", "dest", "system", "name", "bios_dir", "path", "member",
        "list_version", "installed_version", "board", "core", "date",
    ), _TEXT),
    "mode": {"enum": ["install", "check", "dry-run", "list"]},
    "state": {"enum": ["present", "wrong_hash", "missing"]},
    "status": {"enum": ["applied", "written", "unreadable", "not_written"]},
    **dict.fromkeys((
        "files", "files_done", "files_total", "bytes", "bytes_done", "bytes_total",
        "bytes_local", "bytes_network", "size", "present", "missing", "wrong_hash",
        "bytes_needed", "data_missing", "not_installable", "installed", "up_to_date",
        "pending", "code", "games", "recognised", "not_games",
    ), _COUNT),
    **dict.fromkeys(("truncated", "ok", "interrupted", "required_only", "applied", "info"), _FLAG),
    **dict.fromkeys(("systems", "other_drives", "dests", "written", "choice"), _NAMES),
    **dict.fromkeys(("platforms", "failed", "skipped", "left_out", "kept", "found",
                     "fallback"), _RECORDS),
}


def _kind(kind: str, keys: tuple[str, ...]) -> dict:
    properties: dict[str, dict] = {"event": {"const": kind}}
    for key in keys:
        properties[key] = (
            {"const": EVENT_SCHEMA} if (kind, key) == ("start", "schema") else KEY_TYPES[key]
        )
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["event", *keys],
        "properties": properties,
    }


def build_schema() -> dict:
    """One line of the stream: an object of one of the kinds, with exactly its keys."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://abdess.github.io/retrobios/api/v1/schemas/install-events.schema.json",
        "title": "RetroBIOS installer event",
        "description": (
            f"One line of install.py --events, event schema {EVENT_SCHEMA}. Written from "
            "EVENT_KEYS in install.py by scripts/generate_event_schema.py. The schema "
            "gains kinds, never keys on an existing kind: a reader skips a kind it "
            "does not know."
        ),
        "type": "object",
        "required": ["event"],
        "properties": {"event": {"enum": list(EVENT_KEYS)}},
        "oneOf": [{"$ref": f"#/$defs/{kind}"} for kind in EVENT_KEYS],
        "$defs": {kind: _kind(kind, keys) for kind, keys in EVENT_KEYS.items()},
    }


def render(schema: dict) -> str:
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the file differs from EVENT_KEYS, writing nothing")
    parser.add_argument("--output", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    text = render(build_schema())
    current = args.output.read_text(encoding="utf-8") if args.output.is_file() else None
    if current == text:
        return 0
    if args.check:
        print(f"{args.output} differs from EVENT_KEYS: run "
              "python scripts/generate_event_schema.py", file=sys.stderr)
        return 1
    write_text_atomic(str(args.output), text)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
