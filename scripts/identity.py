"""Report one content stored under identities that disagree (resolve/identity.py)."""

from __future__ import annotations

from core.cli import add_repo_inputs
from resolve.identity import format_duplicate, scan


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Report one content stored under identities that disagree.",
    )
    add_repo_inputs(parser, "bios")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--strict", action="store_true", help="exit non-zero when any is found"
    )
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(args, parser, ["bios_dir"])
    from core.cli import require_directory

    require_directory(args.bios_dir)

    duplicates = scan(args.bios_dir)
    if args.json:
        import json

        print(
            json.dumps(
                [
                    {
                        "sha1": d.sha1,
                        "size": d.size,
                        "paths": d.paths,
                        "manufacturers": d.manufacturers,
                    }
                    for d in duplicates
                ],
                indent=2,
            )
        )
    else:
        for duplicate in duplicates:
            print(f"  {format_duplicate(duplicate)}")
        print(f"\n{len(duplicates)} contents stored under contradicting identities.")

    return 1 if (duplicates and args.strict) else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
