"""Write platforms/romfolders/<setup>.yml from each setup's pinned source.

    python -m scripts.scraper.romfolders --all
    python -m scripts.scraper.romfolders --setup batocera --dry-run
    python -m scripts.scraper.romfolders --all --offline   # cache only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import Fetcher, SourceError, dump_setup, load_sources, scrape_setup
from core.upstream import UpstreamError
from core.artifacts import write_if_changed

DEFAULT_DIR = Path("platforms") / "romfolders"


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--setup", action="append", help="setup id (repeatable)")
    which.add_argument("--all", action="store_true", help="every setup of the sources file")
    which.add_argument("--list", action="store_true", help="list the setups and their format")
    parser.add_argument("--sources", type=Path, default=DEFAULT_DIR / "_sources",
                        help="the setups, their repositories and pinned revisions")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_DIR,
                        help=f"where <setup>.yml is written (default {DEFAULT_DIR})")
    parser.add_argument("--offline", action="store_true", help="read the revision cache only")
    parser.add_argument("--dry-run", action="store_true", help="print counts, write nothing")
    args = parser.parse_args()

    sources = load_sources(args.sources)
    if args.list:
        for setup, spec in sources.items():
            print(f"{setup:16} {spec.get('format') or '-':14} {spec.get('name', '')}")
        return 0
    wanted = list(sources) if args.all else args.setup
    unknown = [s for s in wanted if s not in sources]
    if unknown:
        print(f"Error: unknown setup(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    failed = 0
    for setup in wanted:
        spec = sources[setup]
        fetcher = Fetcher(spec.get("sources", {}), offline=args.offline)
        try:
            doc = scrape_setup(setup, spec, fetcher)
        except (SourceError, UpstreamError, ValueError, KeyError, OSError) as exc:
            print(f"FAIL {setup}: {exc}", file=sys.stderr)
            failed += 1
            continue
        print(f"{setup}: {len(doc['folders'])} folders")
        if not args.dry_run:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            write_if_changed(str(args.output_dir / f"{setup}.yml"), dump_setup(doc))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
