"""The project's own clone: git output lines and the project's main line."""

from __future__ import annotations

import re
import subprocess



def _git_lines(*args: str) -> list[str] | None:
    """Output lines of a git command, or None when git refuses it."""
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


PROJECT_URLS = (
    "https://github.com/Abdess/retrobios",
    "https://github.com/Abdess/retroarch_system",
)


def _repo_key(url: str) -> str:
    """owner/name of a clone URL, whatever its scheme."""
    path = url.strip().rstrip("/").removesuffix(".git")
    return "/".join(re.split(r"[/:]", path)[-2:]).casefold()


def _project_main_line() -> str | None:
    """The project's main line, fetched when this clone does not hold it.

    A fork's clone has origin alone. Once the commit is pushed to the fork's
    main, origin/main is HEAD and the diff against it was empty, so --changed
    found nothing and exited 0. A remote added as CONTRIBUTING says and never
    fetched did the same: upstream/main did not exist and origin/main won.
    None leaves the upstream/ and origin/ lines in charge when the clone has
    no remote at all and only its uncommitted files can be read.
    """
    remotes = _git_lines("remote") or []
    if not remotes:
        return None
    project = {_repo_key(url) for url in PROJECT_URLS}
    source = PROJECT_URLS[0]
    for remote in remotes:
        urls = _git_lines("remote", "get-url", "--all", remote) or []
        if any(_repo_key(url) in project for url in urls):
            if _git_lines("rev-parse", "--verify", "--quiet", f"{remote}/main"):
                return f"{remote}/main"
            source = remote
            break
    fetched = subprocess.run(
        ["git", "fetch", "--quiet", "--no-tags", source, "main"],
        capture_output=True, text=True, check=False,
    )
    if fetched.returncode != 0:
        raise RuntimeError(
            f"this clone does not hold the main of {PROJECT_URLS[0]}, and "
            f"fetching its main from {source} failed: {fetched.stderr.strip()}"
        )
    return "FETCH_HEAD"
