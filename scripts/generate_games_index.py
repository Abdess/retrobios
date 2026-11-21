"""Publish what the installer reads to install for the games on a card.

The installer's "For the games on this card" mode reads the card's rom
folders, identifies each game and installs only the BIOS those games need.
This step joins the sources that answer each part and writes them next to the
install lists, under install/games/:

- index.json: format version, a digest of the data, and every published
  file with its size, its gzip size (raw.githubusercontent.com compresses on
  request) and its sha256, so a phone fetches only what its card needs.
- setups/<setup>.json: the setup's rom folders (platforms/romfolders/),
  resolved to repository systems and profiles, with the key of each folder's
  fallback set.
- fallback/<platform>.json: per system and default core, the files the
  platform's install list carries for them (computed from install/<platform>.json
  with the installer's own core narrowing), their sizes and whether each is
  required. What an unrecognised game keeps.
- systems/<system>.json: identification (games/catalogs/, crc32 + size to a
  region and a title, disc serials to a region), header readers
  (games/headers.yml), region rules per profile (games/regions.yml joined with
  the profiles' region: fields) and per-game extra files (games/extras.yml).
- arcade/<profile>.json: game set to BIOS parent and device sets
  (games/arcade/).

Nothing here is written by hand: a second run writes the same bytes.

    python scripts/generate_games_index.py
    python scripts/generate_games_index.py --check   # exit 1 if a file would change
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.artifacts import repository_output_lock
from core.cli import run_cli
from games.inputs import OUTPUT
from games.run import index


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", type=Path, default=OUTPUT,
                        help=f"where the index is written (default {OUTPUT})")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when a file would change, naming what differs (implies --quiet)")
    parser.add_argument("--quiet", action="store_true", help="print only failures")
    args = parser.parse_args()
    if args.check:
        return index(args)
    with repository_output_lock(str(args.output_dir)):
        return index(args)


if __name__ == "__main__":
    run_cli(main)
