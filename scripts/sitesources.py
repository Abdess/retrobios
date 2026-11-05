"""Permalinks into the sources a profile cites.

A citation is only checkable if it points at the revision the profile
was written against, so a permalink is pinned, never guessed."""

from __future__ import annotations

import argparse
import functools
import json
import re
import sys
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import upstream
from siterender import _by_mode
from sourceref import (
    _HEX_ADDRESS_RE, _prose_runs, is_binary_citation, ref_role, source_ref_values,
    split_source_ref,
)


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

# Forges the pages link into but upstream.py does not read from. Each is
# reached by browser only, so the Repo carries no API or raw base.
_BROWSE_ONLY = {
    "voidpoint.io": "gitlab",
    "bitbucket.org": "bitbucket",
    "sourceforge.net": "sourceforge",
    "archive.softwareheritage.org": "swh",
}


def _browse_repo(url: str) -> upstream.Repo | None:
    """The repository a profile URL names, on any forge the pages can link.

    Profiles pinned on SourceForge, voidpoint.io, Bitbucket or Software
    Heritage showed no revision and no linked citation: parse_repo knows
    only the forges profile_sync fetches from.
    """
    repo = upstream.parse_repo(url)
    if repo is not None or not url:
        return repo
    parts = urllib.parse.urlsplit(url.strip())
    family = _BROWSE_ONLY.get(parts.netloc)
    segments = [seg for seg in parts.path.split("/") if seg]
    if family == "gitlab":
        if "-" in segments:
            segments = segments[: segments.index("-")]
        if len(segments) < 2:
            return None
        owner, name = "/".join(segments[:-1]), segments[-1]
    elif family == "bitbucket" and len(segments) >= 2:
        owner, name = segments[0], segments[1]
    elif family == "sourceforge" and len(segments) >= 3 and segments[0] == "p":
        owner, name = segments[1], segments[2]
    elif family == "swh":
        # A revision URL names no project: the pin alone addresses the tree.
        owner, name = "softwareheritage", "revision"
    else:
        return None
    return upstream.Repo(parts.netloc, family, "", "", owner, name.removesuffix(".git"))


def _forge_sources(profile: dict, label: str = "") -> list[tuple[upstream.Repo, str]]:
    """Supported source repositories and immutable revisions for a profile."""
    candidates: list[tuple[upstream.Repo, str]] = []
    seen: set[tuple[str, str, str]] = set()
    source_repos: set[tuple[str, str]] = set()

    for field in ("source", "upstream"):
        for value, pin, fallback in _repo_pins(profile, field, label):
            repo = _browse_repo(value)
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
    if repo.family == "bitbucket":
        url = f"{base}/src/{pin}/{quoted_path}"
        if start is not None:
            url += f"#lines-{start}" + (f":{end}" if end is not None and end != start else "")
        return url
    if repo.family == "sourceforge":
        # The Allura code browser takes no line range: the file at the pin.
        return f"https://{repo.host}/p/{repo.owner}/{repo.name}/ci/{pin}/tree/{quoted_path}"
    if repo.family == "swh":
        url = f"https://{repo.host}/browse/revision/{pin}/?path={quoted_path}"
        if start is not None:
            url += f"#L{start}" + (f"-L{end}" if end is not None and end != start else "")
        return url
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

# The tree listings profile_sync caches, read only by the command that
# writes SOURCE_PATHS. The pages read that file: the deploy has no tree
# cache, and a citation it could not check was linked into whichever
# repository the profile declared, 30 of them to a 404.
TREE_CACHE = Path(__file__).resolve().parent.parent / upstream.CACHE_DIR
SOURCE_PATHS = (Path(__file__).resolve().parent.parent
                / "website" / "src" / "data" / "source-paths.json")


def tree_key(repo: upstream.Repo, pin: str) -> str:
    """How SOURCE_PATHS names one repository at one revision."""
    return f"{repo.host}/{repo.slug}@{pin}"


@functools.lru_cache(maxsize=None)
def _verified() -> dict[str, frozenset[str]]:
    """The committed record, empty when it has not been written."""
    try:
        data = json.loads(SOURCE_PATHS.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    return {key: frozenset(paths) for key, paths in data.items()}


@functools.lru_cache(maxsize=None)
def _tree_paths(repo: upstream.Repo, pin: str) -> frozenset[str]:
    """The cited paths of a repository at a revision that its tree holds."""
    return _verified().get(tree_key(repo, pin), frozenset())


def tree_holds(repo: upstream.Repo, pin: str, path: str) -> bool:
    """Whether ``path`` was found in the repository's tree at ``pin``.

    trident cites src/core/loader/ncch.cpp, a Panda3DS file, and the page
    linked it into 3dsTrident, where it is a 404. A path no tree confirmed,
    on a forge whose tree cannot be read or a revision not cached when the
    record was written, is not linked: no link beats a link to nothing.
    """
    return path in _tree_paths(repo, pin)


def _holder(
    candidates: list[tuple[upstream.Repo, str]], path: str,
) -> tuple[upstream.Repo, str] | None:
    """The pinned repository that holds ``path``, source before upstream as
    profile_sync.select_views orders them."""
    return next((cand for cand in candidates if tree_holds(*cand, path)), None)


def _cached_tree(
    repo: upstream.Repo, pin: str, cache_dirs: list[Path], fetch: bool = False,
) -> frozenset[str] | None:
    """Every file of a repository at a revision, None when not cached or
    truncated (a missing path would then prove nothing). Each cache is read
    in turn. With *fetch*, a tree none holds is fetched into the last one."""
    if not repo.api_base:
        return None  # a browse-only forge: no listing to read
    for index, cache_dir in enumerate(cache_dirs):
        online = fetch and index == len(cache_dirs) - 1
        try:
            paths, truncated = upstream.list_tree(repo, pin, str(cache_dir), offline=not online)
        except upstream.UpstreamError as exc:
            print(f"  {tree_key(repo, pin)}: {exc}", file=sys.stderr)
            return None
        if paths and not truncated:
            return frozenset(paths)
    return None


def _walk(value: object) -> Iterator[tuple[str, object]]:
    """Every (key, value) of a profile, nested lists and mappings included."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def cited_paths(profile: dict) -> set[str]:
    """Every path a page of the profile could link: the parts of each
    source_ref and the file:line citations of its prose."""
    paths: set[str] = set()
    for key, value in _walk(profile):
        if key == "source_ref" and isinstance(value, (str, dict)):
            for _label, refs in source_ref_values(value):
                paths.update(ref_role(part.path)[1] for part in split_source_ref(refs))
        elif isinstance(value, str) and ":" in value:
            for _n, _span, _spans, parts, _run, _wrapped in _prose_runs(value):
                paths.update(part.path for part in parts)
    return {path for path in paths
            if _PATH_RE.fullmatch(path) and not is_binary_citation(path)}


def profile_trees(profile: dict) -> list[tuple[upstream.Repo, str]]:
    """Every repository and revision a page of the profile can link into."""
    found: list[tuple[upstream.Repo, str]] = []
    labels = {""} | {
        str(mode) for field in ("source", "upstream", "source_commit", "upstream_commit")
        if isinstance(profile.get(field), dict) for mode in profile[field]}
    for label in sorted(labels):
        for pair in _forge_sources(profile, label) + list(role_sources(profile, label).values()):
            if pair not in found:
                found.append(pair)
    return found


def _listed_directories(
    repo: upstream.Repo, pin: str, paths: set[str], cache_dirs: list[Path], fetch: bool,
) -> frozenset[str] | None:
    """The cited paths found by listing their directories one by one, for a
    tree the forge truncates (aps3e vendors RPCS3 whole). A directory that
    cannot be listed confirms none of its paths. None off GitHub, the one
    forge with that call, and None when no directory could be listed: the
    tree was not read, so its record is kept (TeknoParrotUI answers 404, and
    each fetch without its cached tree dropped its four paths)."""
    if repo.family != "github":
        return None
    found: set[str] = set()
    listed = False
    for folder in sorted({path.rpartition("/")[0] for path in paths} - {""}):
        names = None
        for index, cache_dir in enumerate(cache_dirs):
            online = fetch and index == len(cache_dirs) - 1
            try:
                names = upstream.list_directory(repo, pin, folder, str(cache_dir), offline=not online)
            except upstream.UpstreamError:
                names = None
            if names is not None:
                break
        listed = listed or names is not None
        found.update(f"{folder}/{name}" for name in names or ())
    return frozenset(found) if listed else None


def build_source_paths(
    profiles: dict, cache_dirs: list[Path], fetch: bool = False,
) -> tuple[dict[str, list[str]], list[str]]:
    """The cited paths each cached tree holds, and the trees not cached."""
    held: dict[str, set[str]] = {}
    unread: set[str] = set()
    for _name, profile in sorted(profiles.items()):
        paths = cited_paths(profile)
        if not paths:
            continue
        for repo, pin in profile_trees(profile):
            tree = _cached_tree(repo, pin, cache_dirs, fetch)
            if tree is None:
                tree = _listed_directories(repo, pin, paths, cache_dirs, fetch)
            if tree is None:
                unread.add(tree_key(repo, pin))
                continue
            # Recorded even when it holds no cited path, so a pinned tree
            # missing from the record is one no run has read.
            held.setdefault(tree_key(repo, pin), set()).update(paths & tree)
    return {key: sorted(paths) for key, paths in sorted(held.items())}, sorted(unread)


def keep_unread(
    held: dict[str, list[str]], unread: list[str], previous: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Carry over what the last record held for the trees this run could not read.

    A tree key names a pinned sha, so what it held then it holds now. A run
    that GitLab rate-limited dropped about twenty trees it never read. A tree
    no run could read is recorded empty: confirming no path, it links none,
    and check_freshness tells it from a pin no run has tried.
    """
    kept = dict(held)
    for key in unread:
        kept.setdefault(key, previous.get(key, []))
    return dict(sorted(kept.items()))


def read_record(path: Path) -> dict[str, list[str]]:
    """The record a previous run wrote, empty when there is none."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def _commit_url(repo: upstream.Repo, pin: str) -> str:
    """Forge-specific browser URL for one commit."""
    base = f"https://{repo.host}/{repo.owner}/{repo.name}"
    if repo.family == "gitlab":
        return f"{base}/-/commit/{pin}"
    if repo.family == "bitbucket":
        return f"{base}/commits/{pin}"
    if repo.family == "sourceforge":
        return f"https://{repo.host}/p/{repo.owner}/{repo.name}/ci/{pin}/"
    if repo.family == "swh":
        return f"https://{repo.host}/browse/revision/{pin}/"
    return f"{base}/commit/{pin}"


def revision_markdown(profile: dict) -> str:
    """Each repository the profile reads, linked at the commit it was read at.

    The page linked the repositories unpinned: the revision every citation
    refers to sat in the YAML alone, for 178 profiles.
    """
    links = [
        f"[{'Software Heritage' if repo.family == 'swh' else repo.slug}@{pin[:12]}]"
        f"({_commit_url(repo, pin)})"
        for repo, pin in _forge_sources(profile)
    ]
    branch = profile.get("source_branch")
    if branch and not isinstance(branch, dict):
        links.append(f"branch `{branch}`")
    elif isinstance(branch, dict):
        links += [f"{mode} branch `{name}`" for mode, name in branch.items()]
    return ", ".join(links)


_GLUE_RE = re.compile(r"(^|/)(libretro|retro_)[^/]*$|(^|/)libretro[^/]*/", re.IGNORECASE)


def role_label(profile: dict, role: str, path: str = "") -> str:
    """Whose code a cited path is, said the way a reader asks it.

    A libretro port carries the emulator's own sources beside its glue: pcem
    cites src/mem.c in the port, which is PCem's code, not the core's.
    """
    if role == "upstream":
        return "upstream emulator"
    if "libretro" not in str(profile.get("type", "")):
        return "this build"
    if _GLUE_RE.search(path):
        return "libretro glue"
    return "emulator code, libretro port"


def role_sources(profile: dict, label: str = "") -> dict[str, tuple[upstream.Repo, str]]:
    """The forge repository and pin behind each role a citation can name."""
    found: dict[str, tuple[upstream.Repo, str]] = {}
    for field in ("source", "upstream"):
        for value, pin, _fallback in _repo_pins(profile, field, label):
            repo = _browse_repo(value)
            if repo is not None and pin and field not in found:
                found[field] = (repo, pin)
    return found


def requested_by(profile: dict, value: str | dict | None) -> str:
    """Whose code the citations of an entry are in, said in words."""
    labels = []
    for _label, refs in source_ref_values(value):
        for part in split_source_ref(refs):
            role, bare = ref_role(part.path)
            if role:
                label = role_label(profile, role, bare)
                if label not in labels:
                    labels.append(label)
    if not labels or not _two_repositories(profile):
        return ""
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + f" and {labels[-1]}"


def _two_repositories(profile: dict) -> bool:
    source, upstream_url = profile.get("source"), profile.get("upstream")
    return bool(source and upstream_url and source != upstream_url)


def _source_ref_markdown(profile: dict, value: str | dict | None) -> str:
    """Render source_ref values as pinned links when their forge is known.

    Each part is followed by whose code it cites, in words, when the profile
    reads two repositories. source_ref_items() gives the same parts with
    that role apart, for a page that names the roles once in a legend.
    """
    rendered_groups = []
    for label, items in source_ref_items(profile, value):
        text = ", ".join(f"{part} ({role})" if role else part for part, role in items)
        if label:
            text = f"**{label}:** {text}"
        rendered_groups.append(text)
    return ", ".join(rendered_groups)


def source_ref_items(profile: dict, value: str | dict | None) -> list[tuple[str, list[tuple[str, str]]]]:
    """Each group of source_ref values: its label and its parts, each part
    as Markdown with the role_label() of the code it cites ("" when the
    profile reads one repository).

    A profile can declare two repositories: the libretro port in ``source`` and
    the original emulator in ``upstream``. A path links into the one whose
    tree SOURCE_PATHS says holds it. Any other path is rendered as plain
    code: a citation with no link still names the file and the lines, while a
    link to the wrong repository is a false citation. An address inside a
    shipped binary reads as one (offset 0x8094-0x80ac in libnes.so).
    """
    groups: list[tuple[str, list[tuple[str, str]]]] = []
    path_re = re.compile(r"^[A-Za-z0-9_.@/+~-]+$")
    for label, refs in source_ref_values(value):
        candidates = _forge_sources(profile, label)
        by_role = role_sources(profile, label)
        rendered: list[tuple[str, str]] = []
        current_role = ""
        binary = ""
        for part in split_source_ref(refs):
            if is_binary_citation(part.path):
                text, binary = _binary_citation(part.path, binary)
                rendered.append((text, ""))
                continue
            binary = ""
            role, bare = ref_role(part.path)
            if bare != part.path or role:
                current_role = role
            elif part.raw and not part.raw[:1].isdigit():
                current_role = ""
            part = type(part)(bare, part.start, part.end, part.raw)
            display = part.path
            if part.start is not None:
                display += f":{part.start}"
                if part.end is not None and part.end != part.start:
                    display += f"-{part.end}"

            # The path is linked as written. A first segment equal to a
            # repository's name proves nothing: PCSX2 keeps its sources in
            # pcsx2/, hatariB vendors Hatari in hatari/, and stripping it
            # broke 470 links. Two repositories and no tree to read: no link.
            selected: tuple[upstream.Repo, str] | None = None
            real_path = part.path
            if path_re.fullmatch(part.path):
                if current_role:
                    # Only the repository the part names, or no link at all.
                    selected = by_role.get(current_role)
                    if selected is not None and not tree_holds(*selected, part.path):
                        selected = None
                else:
                    selected = _holder(candidates, part.path)

            role = (role_label(profile, current_role, part.path)
                    if current_role and _two_repositories(profile) else "")
            if selected is None:
                rendered.append((f"`{display}`", role))
            else:
                repo, pin = selected
                url = _source_permalink(
                    repo, pin, real_path, part.start, part.end
                )
                rendered.append((f"[`{display}`]({url})", role))

        groups.append((label, rendered or [(f"`{refs}`", "")]))
    return groups


def _binary_citation(path: str, previous: str) -> tuple[str, str]:
    """A part citing code inside a shipped binary, and the binary it names.

    `Nesoid 2.5.0 libnes.so 0x455a4-0x45694, 0x8094-0x80ac` cites two
    ranges of one library: the bare address continues the binary before it.
    No revision of a repository holds those bytes, so nothing is linked.
    """
    found = _HEX_ADDRESS_RE.search(path)
    if found is None:
        return f"`{path}`", path
    binary = path[:found.start()].rstrip(" :") or previous
    if not binary:
        return f"`{path}`", ""
    return f"offset `{path[found.start():]}` in `{binary}`", binary


def link_prose_citations(profile: dict, text: str) -> str:
    """Prose file:line citations as pinned links, where the target is certain.

    profile_sync keeps these citations on their pin, and the page printed
    4,328 of them as plain text. A citation links only when the path is
    rooted (it holds a directory) or is one a structured source_ref of the
    profile already uses: a bare name could be anywhere in the tree, and a
    link to the wrong file is a false citation. Of the repositories a profile
    reads, the one its role word names is taken, else the one tree holding
    the path: held by both, the citation does not say which it means.
    Text already in backticks or in a link is left alone.
    """
    candidates = _forge_sources(profile)
    if not candidates or ":" not in text:
        return text
    by_role = role_sources(profile)
    structured = {
        part.path
        for entry in profile.get("files") or []
        if isinstance(entry, dict)
        for _label, refs in source_ref_values(entry.get("source_ref"))
        for part in split_source_ref(refs)
    }
    out = []
    for line in text.split("\n"):
        guarded = _guarded_spans(line)
        edits = []
        for _n, path_span, spans, parts, _run, wrapped in _prose_runs(line):
            path = parts[0].path
            if wrapped or " " in path or not _PATH_RE.fullmatch(path):
                continue
            if "/" not in path and path not in structured:
                continue
            if any(lo <= path_span[0] < hi for lo, hi in guarded):
                continue
            role = parts[0].role
            # `upstream a.c:5` names its repository: none other is linked.
            named = [by_role[role]] if role in by_role else [] if role else candidates
            holders = [tree for tree in named if tree_holds(*tree, path)]
            if len(holders) != 1:
                continue
            repo, pin = holders[0]
            for index, ((lo, hi), part) in enumerate(zip(spans, parts)):
                start = path_span[0] if index == 0 else lo
                url = _source_permalink(repo, pin, part.path, part.start, part.end)
                edits.append((start, hi, f"[`{line[start:hi]}`]({url})"))
        for start, end, link in sorted(edits, reverse=True):
            line = line[:start] + link + line[end:]
        out.append(line)
    return "\n".join(out)


_PATH_RE = re.compile(r"^[A-Za-z0-9_.@/+~-]+$")


def _guarded_spans(line: str) -> list[tuple[int, int]]:
    """Code spans and links of a markdown line."""
    return [m.span() for m in re.finditer(r"`[^`]*`|\[[^\]]*\]\([^)]*\)", line)]


# Where a platform's list was read: the forge, the repository, the revision
# and the path inside it, out of the URL its scraper pinned.
_LIST_URL_RES = (
    re.compile(r"^https://raw\.githubusercontent\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
               r"(?P<rev>[^/]+)/(?P<path>.+)$"),
    re.compile(r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/(?:blob|tree)/"
               r"(?P<rev>[^/]+)(?:/(?P<path>.+))?$"),
    re.compile(r"^https://codeload\.github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
               r"tar\.gz/(?P<rev>[^/]+)$"),
    re.compile(r"^https://(?P<host>gitlab\.com)/(?P<owner>[^/]+)/(?P<repo>[^/]+)/-/"
               r"(?:raw|blob)/(?P<rev>[^/]+)/(?P<path>.+)$"),
)
_BRANCHES = frozenset({"master", "main", "db"})


@dataclass(frozen=True)
class ListSource:
    """A platform's list as its scraper read it."""

    host: str
    owner: str
    repo: str
    rev: str
    path: str

    @property
    def moving(self) -> bool:
        """The revision is a branch: what was read is not recorded."""
        return not self.rev or self.rev in _BRANCHES

    @property
    def label(self) -> str:
        """`batocera-systems at tag batocera-43.1`, said in words."""
        name = self.path.rsplit("/", 1)[-1] if self.path else f"{self.repo} repository"
        if not self.rev:
            return f"{name}, default branch"
        if re.fullmatch(r"[0-9a-f]{40}", self.rev):
            return f"{name} at commit {self.rev[:12]}"
        if self.moving:
            return f"{name} on branch {self.rev}"
        return f"{name} at tag {self.rev}"

    def browse(self, path: str = "", start: int | None = None,
               end: int | None = None) -> str:
        """The page a reader opens: the file, or the tree, at the revision."""
        path = path or self.path
        if self.host == "gitlab.com":
            url = f"https://gitlab.com/{self.owner}/{self.repo}/-/blob/{self.rev}/{path}"
            anchor = f"#L{start}" + (f"-{end}" if end and end != start else "")
        else:
            base = f"https://github.com/{self.owner}/{self.repo}"
            if not self.rev:
                return base
            kind = "blob" if path else "tree"
            url = f"{base}/{kind}/{self.rev}" + (f"/{path}" if path else "")
            anchor = f"#L{start}" + (f"-L{end}" if end and end != start else "")
        return url + (anchor if start else "")


def list_source(url: str) -> ListSource | None:
    """The forge, repository, revision and path of a platform's `source:`."""
    url = str(url or "").strip()
    for pattern in _LIST_URL_RES:
        found = pattern.match(url)
        if found:
            parts = found.groupdict()
            return ListSource(parts.get("host") or "github.com", parts["owner"],
                              parts["repo"], parts["rev"], parts.get("path") or "")
    bare = re.match(r"^https://github\.com/([^/]+)/([^/]+?)/?$", url)
    if bare:
        return ListSource("github.com", bare[1], bare[2], "", "")
    return None


def launcher_ref_markdown(source: ListSource | None, ref: str) -> str:
    """A launcher record's source_ref, each part a pinned link.

    Linked only where the caller knows the launcher code sits in the
    repository and revision of the platform's list. Otherwise each part is
    plain code: a link to another repository is a false citation.
    """
    rendered: list[str] = []
    for part in split_source_ref(ref):
        display = part.path.rsplit("/", 1)[-1]
        if part.start is not None:
            display += f":{part.start}"
            if part.end is not None and part.end != part.start:
                display += f"-{part.end}"
        if source is None or not source.rev or not _PATH_RE.fullmatch(part.path):
            rendered.append(f"`{display}`")
        else:
            rendered.append(f"[`{display}`]({source.browse(part.path, part.start, part.end)})")
    return ", ".join(rendered)


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Record which cited source paths the cached upstream trees hold",
    )
    parser.add_argument(
        "--cache-dir", type=Path, action="append",
        help=f"tree listings profile_sync cached, read in the order given (default: {TREE_CACHE})",
    )
    parser.add_argument(
        "--fetch", action="store_true",
        help="fetch a tree no cache holds into the last --cache-dir",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="profiles whose citations are checked (default: %(default)s)",
    )
    parser.add_argument(
        "--output", type=Path, default=SOURCE_PATHS,
        help="record the site reads (default: %(default)s)",
    )
    args = parser.parse_args()
    cache_dirs = args.cache_dir or [TREE_CACHE]
    if not args.fetch and not any(path.is_dir() for path in cache_dirs):
        print(f"Error: no tree cache at {', '.join(map(str, cache_dirs))}", file=sys.stderr)
        return 1
    from common import load_emulator_profiles, write_if_changed  # noqa: PLC0415

    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    held, unread = build_source_paths(profiles, cache_dirs, args.fetch)
    held = keep_unread(held, unread, read_record(args.output))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(str(args.output), json.dumps(held, indent=1, sort_keys=True) + "\n")
    print(f"{sum(map(len, held.values()))} paths held in {len(held)} trees, "
          f"{len(unread)} trees not cached: {args.output}")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
