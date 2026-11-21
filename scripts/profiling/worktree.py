"""The git state a profile pass reads: uncommitted profiles, the branch's profiles, the project's main line."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def refuse_dirty_tree(emulators_dir: str, names: list[str]) -> None:
    """Writes need a clean copy of each profile they touch to roll back to.

    Only the selected profiles count: a pass writing one profile after
    another used to refuse every profile after the first it wrote.
    """
    try:
        dirty = emulators_dir_is_dirty(emulators_dir, names)
    except RuntimeError as e:
        print(f"{e}. Pass --force to write anyway.", file=sys.stderr)
        raise SystemExit(1) from e
    if dirty:
        # Another session may own the change, so the refusal names the files:
        # --force writes over them.
        one = len(dirty) == 1
        print(
            f"{', '.join(dirty)} {'has' if one else 'have'} uncommitted changes: "
            f"commit {'it' if one else 'them'} or pass --force, which writes over "
            f"{'it' if one else 'them'}.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def emulators_dir_is_dirty(emulators_dir: str, names: list[str] | None = None) -> list[str]:
    """The files of the profile directory that carry uncommitted changes.

    Paths read as the status prints them, from the repository root.

    ``names`` narrows the question to those profiles. Git is asked from
    inside the directory, so a profile tree that lives in another
    repository answers for itself. A directory git cannot read is never
    reported clean: the writes have nothing to roll back to.
    """
    paths = [f"{name}.yml" for name in names] if names is not None else ["."]
    result = subprocess.run(
        ["git", "-C", emulators_dir, "status", "--porcelain", "--", *paths],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"cannot read the git status of {emulators_dir}: {result.stderr.strip()}"
        )
    return sorted(
        line[3:].split(" -> ")[-1].strip('"')
        for line in result.stdout.splitlines()
        if line.strip()
    )


def _git_lines(args: list[str]) -> list[str]:
    from core.gitclone import GitRefused, required_git_lines

    try:
        return required_git_lines(*args)
    except GitRefused as exc:
        raise SystemExit(f"ERROR: {exc}") from exc


def branch_profiles(emulators_dir: str, base: str, added_only: bool) -> list[str]:
    """Names of the profiles the branch adds (or edits) against ``base``.

    The diff starts at the merge base, so commits main gained since the
    branch point are not counted, and ends at the working tree, so a
    profile not yet committed is checked too. A rename reads as an addition.
    """
    if subprocess.run(["git", "rev-parse", "--verify", "--quiet", base],
                      capture_output=True, check=False).returncode:
        remote = base.split("/", 1)[0] if "/" in base else "upstream"
        raise SystemExit(f"ERROR: {base} is not in this clone: run git fetch {remote} first")
    merge_base = _git_lines(["merge-base", base, "HEAD"])[0]
    paths = _git_lines([
        "diff", "--name-only", "--no-renames",
        "--diff-filter=A" if added_only else "--diff-filter=AM",
        merge_base, "--", emulators_dir,
    ])
    paths += _git_lines([
        "ls-files", "--others", "--exclude-standard", "--full-name",
        "--", emulators_dir,
    ])
    top = Path(_git_lines(["rev-parse", "--show-toplevel"])[0])
    root = Path(emulators_dir).resolve()
    return sorted({
        full.stem
        for path in paths
        if (full := (top / path).resolve()).suffix == ".yml" and full.parent == root
    })


def project_base() -> str:
    """The project's main line, the base --changed compares with by default.

    In a fork's clone origin/main is the fork: once the branch is pushed it
    is HEAD, and --changed --strict found nothing and passed while the PR's
    CI then failed. validate_pr.py resolves the same line the same way.
    """
    from core.gitclone import compare_base

    return compare_base() or "HEAD"
