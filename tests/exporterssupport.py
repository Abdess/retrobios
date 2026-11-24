"""Fixtures shared by the native exporter test modules."""

from __future__ import annotations

import tests

from pathlib import Path

from resolve.reconcile import build_native_model


REPO_ROOT = Path(__file__).resolve().parent.parent

UPSTREAM_CACHE = REPO_ROOT / ".cache" / "upstream-native"


TRUTH = {
    "systems": {
        "sony-playstation": {
            "files": [
                {
                    "name": "scph5501.bin",
                    "path": "psx/scph5501.bin",
                    "md5": "490f666e1afb15b7362b406ed1cea246",
                    "size": 524288,
                    "required": True,
                    "_cores": ["duckstation"],
                },
                {
                    "name": "scph7001.bin",
                    "path": "psx/scph7001.bin",
                    "md5": "1e68c231d0896b7eadcad1d7d8e76129",
                    "size": 524288,
                    "required": False,
                    "_cores": ["duckstation"],
                },
                # Carries an md5 on purpose: without one it would be dropped
                # for being incomplete, and the placeholder guard would never
                # be the reason it stayed out.
                {
                    "name": "<user-selected>.bin",
                    "path": "psx/PLACEHOLDER-MUST-NOT-SHIP.bin",
                    "md5": "00000000000000000000000000000000",
                    "size": 1,
                    "required": False,
                    "_cores": ["duckstation"],
                },
            ],
        },
    },
}

# The profiles that name the runners: beetle_psx answers to the buildbot's
# mednafen_psx, duckstation has a standalone build.
PROFILES = {
    "beetle_psx": {"type": "libretro", "cores": ["mednafen_psx"]},
    "duckstation": {"type": "standalone + libretro"},
}

SCRAPED = {
    # The cores the platform runs, by its own names: an addition is written
    # with the runner that wants it.
    "cores": ["atari800", "duckstation", "fuse", "melonds", "o2em", "picodrive",
              "snes9x", "beetle_psx"],
    "standalone_cores": ["duckstation"],
    "systems": {
        "sony-playstation": {
            "native_id": "psx",
            "files": [
                {
                    "name": "scph5501.bin",
                    "destination": "psx/scph5501.bin",
                    "native_system": "psx",
                    "native_name": "Sony PlayStation",
                    "md5": "deadbeefdeadbeefdeadbeefdeadbeef",
                    "core": "libretro/duckstation",
                    "required": True,
                },
                {
                    "name": "unknown-to-truth.bin",
                    "destination": "psx/unknown-to-truth.bin",
                    "native_system": "psx",
                    "native_name": "Sony PlayStation",
                    "md5": "11111111111111111111111111111111",
                    "core": "libretro/duckstation",
                    "required": True,
                },
            ],
        },
    },
}


def model(truth: dict = TRUTH, scraped: dict | None = SCRAPED):
    return build_native_model(truth, scraped)
