#!/usr/bin/env python3
"""Write the notes of a release from its record.

The notes carried the pack table, typed by hand from figures release.json
already held: a copied cell or an old collection total at the top is how
issue 81 happened. Install commands, the parts sentence and the table come
from the record and the registry. Each row links the files of this release,
which sit right below the notes, and the setups the registry does not mark
release_pack are named with the command. The text is a beginner's page: one
idea per line, plain words (owner, 2026-11-10). The maintainer writes
what changed, and that text is appended as given once it holds none of the
REFUSED phrases.

The notes end with the people to thank and the full changelog, from the
previous release's record commit (the first commit release.json gave the
previous tag) to the new tag. The thanks name everyone who helped since the
repository started, read with gh: a login is only ever the one GitHub links
to the work, never one guessed from a git author name. The owner, bots and
spam are left out (LEFT_OUT). --thanks FILE passes a checked list instead
of the one gh gives.

Usage:
    python scripts/release_notes.py --whats-new tmp/whats-new.md --output notes.md
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from model import releaserecord
from core.cli import require_directory
from core.paths import PLATFORMS_DIR
from core.artifacts import write_text_atomic
from release.notes import (
    changelog_url,
    closing_lines,
    gather_thanks,
    previous_record_commit,
    refused_words,
    render,
)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Write a release's notes")
    parser.add_argument("--record", default=releaserecord.RECORD, type=Path,
                        help="release record (default: %(default)s)")
    parser.add_argument("--whats-new", required=True, type=Path,
                        help="what changed since the previous release, written by hand")
    parser.add_argument("--platforms-dir", default=PLATFORMS_DIR,
                        help="registry read for each pack's extract folder (default: %(default)s)")
    parser.add_argument("--thanks", type=Path,
                        help="checked Thanks lines to print instead of the ones gh gives")
    parser.add_argument("--output", required=True, type=Path,
                        help="notes file to write, passed to gh release create --notes-file")
    args = parser.parse_args()
    require_directory(args.platforms_dir, "--platforms-dir")

    record = releaserecord.load_record(args.record)
    if not record.get("packs"):
        print(f"Error: {args.record} records no pack", file=sys.stderr)
        return 1
    whats_new = args.whats_new.read_text(encoding="utf-8")
    if not whats_new.strip():
        print(f"Error: {args.whats_new} is empty", file=sys.stderr)
        return 1
    refused = refused_words(whats_new)
    if refused:
        print(f"Error: {args.whats_new} says {', '.join(repr(w) for w in refused)}. State what"
              " changed and how it was checked, not a verdict on other projects or a"
              " promise the gap analysis contradicts", file=sys.stderr)
        return 1
    try:
        base = previous_record_commit(record["tag"])
        if args.thanks:
            thanks = [line for line in args.thanks.read_text(encoding="utf-8").splitlines()
                      if line.strip()]
        else:
            thanks = gather_thanks()
    except (subprocess.CalledProcessError, ValueError, KeyError, OSError) as exc:
        detail = getattr(exc, "stderr", "") or exc
        print(f"Error: cannot gather the thanks: {str(detail).strip()}. Pass a checked list"
              " with --thanks FILE", file=sys.stderr)
        return 1
    closing = closing_lines(thanks, changelog_url(base, record["tag"]))
    write_text_atomic(str(args.output), render(record, args.platforms_dir, whats_new, closing))
    print(f"Wrote {args.output} for {record['tag']}, {len(record['packs'])} packs")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
