"""Commit message rules of this repository, in one place.

The local commit-msg hook calls this file, and autorun checks every job's
subject with it when the job list loads. Kept in the tree, the rules hold in
any clone and in CI: a copy in the hook alone left the runner checking only
the shape there.

Usage as a hook: python scripts/commit_rules.py MESSAGE_FILE
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MAX_SUBJECT = 50
SUBJECT_TYPES = re.compile(r"^(feat|refactor|chore|docs|fix): [a-z0-9]")
REFUSED_WORDS = re.compile(
    r"\b(bug|regression|revert|dead code|broken|wrong|hack|workaround|"
    r"comprehensive|implement)",
    re.IGNORECASE,
)
# A numbered pointer at a private review ("audit 24", "review 3", "round 5")
# names notes no clone holds. tests/test_prose_style.py refuses the same tags
# in tracked files, and history cannot be rewritten once pushed.
REVIEW_TAG = re.compile(
    r"\b(audit|review|round|batch|finding)s? #?\d+|\baudit (batch|findings?)\b"
    r"|[a-z]+_audit_\d+",
    re.IGNORECASE,
)
CO_AUTHOR = re.compile(r"^co-authored-by", re.IGNORECASE | re.MULTILINE)


def problems(message: str) -> list[str]:
    """What this repository refuses in a commit message, first line first."""
    found = []
    subject = message.split("\n", 1)[0]
    if len(subject) > MAX_SUBJECT:
        found.append(f"subject is {len(subject)} characters, {MAX_SUBJECT} at most: {subject}")
    if not SUBJECT_TYPES.match(subject):
        found.append("subject must read 'type: description' (feat, refactor, chore, docs, fix)")
    text = "\n".join(line for line in message.splitlines() if not line.startswith("#"))
    if REFUSED_WORDS.search(text):
        found.append("the message uses a word this repository's history does not carry")
    if REVIEW_TAG.search(text):
        found.append("say what the change does, not which review asked for it")
    if CO_AUTHOR.search(message):
        found.append("no Co-Authored-By trailer here")
    return found


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
