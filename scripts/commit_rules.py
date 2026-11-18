"""Commit message rules of this repository, in one place.

The local commit-msg hook calls this file, and autorun checks every job's
subject with it when the job list loads. Kept in the tree, the rules hold in
any clone and in CI: a copy in the hook alone left the runner checking only
the shape there.

Usage as a hook: python scripts/commit_rules.py MESSAGE_FILE
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devtools.commitrules import problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description="Check a commit message against the rules above")
    parser.add_argument("message_file", type=Path, help="the message file a commit-msg hook receives")
    args = parser.parse_args(argv[1:])
    found = problems(args.message_file.read_text(encoding="utf-8", errors="replace"))
    for problem in found:
        print(f"commit-msg: {problem}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
