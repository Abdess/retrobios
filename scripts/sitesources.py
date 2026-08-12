"""Permalinks into the sources a profile cites.

A citation is only checkable if it points at the revision the profile
was written against, so a permalink is pinned, never guessed."""

from __future__ import annotations

from siterender import _by_mode
import re
from profile_sync import source_ref_values
from profile_sync import split_source_ref
import upstream
import urllib.request
def _repo_pins(profile: dict, field: str, label: str) -> list[tuple[str, str, str]]:
    """Pair each declared repository URL with its own revision.

    A profile whose builds live in separate repositories keys both the URL
    and the revision by build mode. Reading them apart would pin a libretro
    fork to the standalone revision and produce a permalink into a tree that
    never held the cited line. Each tuple is (url, pin, source_commit
    fallback for that same mode).
    """
    raw = profile.get(field, "")
    pin_field = profile.get(f"{field}_commit") or ""
    source_field = profile.get("source_commit") or ""

    if not isinstance(raw, dict):
        if not raw:
            return []
        return [
            (
                str(raw),
                _by_mode(pin_field, label),
                _by_mode(source_field, label),
            )
        ]

    # The requested build mode first, so it wins when several repositories
    # would otherwise be equally good candidates.
    ordered = ([label] if label and label in raw else []) + [
        key for key in raw if key != label
    ]
    return [
        (str(raw[key]), _by_mode(pin_field, key), _by_mode(source_field, key))
        for key in ordered
        if raw.get(key)
    ]

def _forge_sources(profile: dict, label: str = "") -> list[tuple[upstream.Repo, str]]:
    """Supported source repositories and immutable revisions for a profile."""
    candidates: list[tuple[upstream.Repo, str]] = []
    seen: set[tuple[str, str, str]] = set()
    source_repos: set[tuple[str, str]] = set()

    for field in ("source", "upstream"):
        for value, pin, fallback in _repo_pins(profile, field, label):
            repo = upstream.parse_repo(value)
            if repo is None:
                continue
            repo_key = (repo.host, repo.slug)
            if field == "upstream" and not pin and repo_key in source_repos:
                pin = fallback
            if not pin:
                continue
            key = (repo.host, repo.slug, pin)
            if key not in seen:
                candidates.append((repo, pin))
                seen.add(key)
            if field == "source":
                source_repos.add(repo_key)
    return candidates

def _source_permalink(repo: upstream.Repo, pin: str, path: str,
                      start: int | None, end: int | None) -> str:
    """Forge-specific browser URL for one file at one immutable revision."""
    quoted_path = urllib.parse.quote(path, safe="/@:+-._~")
    base = f"https://{repo.host}/{repo.owner}/{repo.name}"
    if repo.family == "github":
        url = f"{base}/blob/{pin}/{quoted_path}"
    elif repo.family == "gitlab":
        url = f"{base}/-/blob/{pin}/{quoted_path}"
    else:
        url = f"{base}/src/commit/{pin}/{quoted_path}"
    if start is not None:
        if repo.family == "gitlab":
            url += f"#L{start}"
            if end is not None and end != start:
                url += f"-{end}"
        else:
            url += f"#L{start}"
            if end is not None and end != start:
                url += f"-L{end}"
    return url

def _source_ref_markdown(profile: dict, value) -> str:
    """Render source_ref values as pinned links when their forge is known.

    A profile can declare two repositories: the libretro port in ``source`` and
    the original emulator in ``upstream``. Which of the two carries a given
    path cannot be decided without reading their trees, and this generator runs
    offline. Rather than guess, an unattributable path is rendered as plain
    code: a citation with no link still names the file and the lines, while a
    link to the wrong repository is a false citation.
    """
    rendered_groups: list[str] = []
    path_re = re.compile(r"^[A-Za-z0-9_.@/+~-]+$")
    for label, refs in source_ref_values(value):
        candidates = _forge_sources(profile, label)
        rendered: list[str] = []
        for part in split_source_ref(refs):
            display = part.path
            if part.start is not None:
                display += f":{part.start}"
                if part.end is not None and part.end != part.start:
                    display += f"-{part.end}"

            selected: tuple[upstream.Repo, str] | None = None
            real_path = part.path
            if path_re.fullmatch(part.path) and candidates:
                for repo, pin in candidates:
                    prefix = f"{repo.name}/"
                    if part.path.startswith(prefix):
                        selected = (repo, pin)
                        real_path = part.path[len(prefix):]
                        break
                if selected is None and len(candidates) == 1:
                    selected = candidates[0]

            if selected is None:
                rendered.append(f"`{display}`")
            else:
                repo, pin = selected
                url = _source_permalink(
                    repo, pin, real_path, part.start, part.end
                )
                rendered.append(f"[`{display}`]({url})")

        text = ", ".join(rendered) if rendered else f"`{refs}`"
        if label:
            text = f"**{label}:** {text}"
        rendered_groups.append(text)
    return "; ".join(rendered_groups)
