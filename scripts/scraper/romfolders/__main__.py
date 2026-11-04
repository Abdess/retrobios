"""Write platforms/romfolders/<setup>.yml from each setup's pinned source.

    python -m scripts.scraper.romfolders --all
    python -m scripts.scraper.romfolders --setup batocera --dry-run
    python -m scripts.scraper.romfolders --all --offline   # cache only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import Fetcher, SourceError, load_sources, scrape_setup
from upstream import UpstreamError  # noqa: E402  (the package puts scripts/ on sys.path)
from artifacts import write_text_atomic  # noqa: E402
from ..base_scraper import _PlatformDumper

DEFAULT_DIR = Path("platforms") / "romfolders"


def dump_setup(doc: dict) -> str:
    return yaml.dump(
        doc, Dumper=_PlatformDumper, sort_keys=False, allow_unicode=True, width=100
    )


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
            target = args.output_dir / f"{setup}.yml"
            text = dump_setup(doc)
            if not target.exists() or target.read_text(encoding="utf-8") != text:
                write_text_atomic(str(target), text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
