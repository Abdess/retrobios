"""Base scraper interface for platform BIOS requirement sources."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import inspect
import json
import re
import sys
import urllib.error
import urllib.request

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, NoReturn, TypeVar

from core.github import github_token
from core.artifacts import write_text_atomic
from core.hashing import git_blob_sha
from core.upstream import (
    MAX_RESPONSE_SIZE,
    RateLimitError,
    UpstreamError,
    make_repo,
    open_retrying,
    read_limited,
    resolve_head,
)
from core.upstream import download as upstream_download
from core.upstream import forge_headers as upstream_headers
from model.safeparse import require_yaml
from model.sources import source_yaml_file

try:
    import yaml
except ImportError:
    require_yaml()  # exits with the install hint


@dataclass
class BiosRequirement:
    """A single BIOS file requirement from a platform source."""

    name: str
    system: str
    sha1: str | None = None
    md5: str | None = None
    crc32: str | None = None
    size: int | None = None
    destination: str = ""
    required: bool = True
    zipped_file: str | None = None  # If set, md5 is for this ROM inside the ZIP
    native_id: str | None = None  # Original system name before normalization
    sha256: str | None = None
    alt_md5: str | None = None
    # How the platform itself writes the file reference. Its own spelling
    # is not always derivable from ours: libretro writes iplromco.dat bare
    # but ep128emu/roms/cpc464.rom with its directory.
    native_path: str | None = None
    # The native system whose entry this one repeats under another system.
    # The platform's own file does not carry the copy: an export skips it.
    mirror_of: str | None = None
    # Fields the platform declares that have no equivalent in our model.
    # Kept verbatim so the native file can be written back unchanged.
    native: dict[str, object] = field(default_factory=dict)


@dataclass
class ChangeSet:
    """Differences between scraped requirements and current config."""

    added: list[BiosRequirement] = field(default_factory=list)
    removed: list[BiosRequirement] = field(default_factory=list)
    modified: list[tuple[BiosRequirement, BiosRequirement]] = field(
        default_factory=list
    )

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def summary(self) -> str:
        parts = []
        if self.added:
            parts.append(f"+{len(self.added)} added")
        if self.removed:
            parts.append(f"-{len(self.removed)} removed")
        if self.modified:
            parts.append(f"~{len(self.modified)} modified")
        return ", ".join(parts) if parts else "no changes"


def md5_field(raw: object) -> tuple[list[str], bool]:
    """The md5 values a batocera-systems item declares, and whether it
    writes them as a list.

    Since batocera.linux 6b08b873 an item's md5 is one string or a list of
    strings, and checkBios accepts a file whose md5 is any of them. The
    platform YAML joins the values with commas, as it does for Recalbox, and
    records the list form so the export writes a list back as a list: a
    one-item list and an empty one are not the same text as a string.
    """
    if raw is None:
        return [], False
    if isinstance(raw, str):
        return ([raw] if raw else []), False
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return [item for item in raw if item], True
    raise ValueError(f"md5 is neither a string nor a list of strings: {raw!r}")


def requirement_entry(req: BiosRequirement) -> dict:
    """Serialize a requirement to a platform YAML file entry.

    Carries the platform's own system id and any field that has no place in
    our model. Without them the transcription is lossy in one direction:
    several native systems collapse onto one slug, and the exporter can no
    longer tell which of them a file came from.
    """
    entry: dict = {
        "name": req.name,
        "destination": req.destination,
        "required": req.required,
    }
    for field_name in ("sha1", "md5", "sha256", "crc32"):
        value = getattr(req, field_name, None)
        if value:
            entry[field_name] = str(value).lower()
    if req.size:
        entry["size"] = req.size
    if req.zipped_file:
        entry["zipped_file"] = req.zipped_file
    if req.alt_md5:
        entry["alt_md5"] = str(req.alt_md5).lower()
    if req.native_id:
        entry["native_system"] = req.native_id
    if req.native_path and req.native_path != req.name:
        entry["native_path"] = req.native_path
    if req.mirror_of:
        entry["mirror_of"] = req.mirror_of
    for key in sorted(req.native):
        value = req.native[key]
        if value not in (None, "", [], {}):
            entry[key] = value
    return entry


SCRAPER_AGENT = "retrobios-scraper/1.0"
GITHUB_API = "https://api.github.com"

_T = TypeVar("_T")


class FetchError(ConnectionError):
    """A GET that failed. `status` is the HTTP status the server answered,
    None when no answer came (DNS, refused connection, timeout)."""

    def __init__(self, url: str, reason: object, status: int | None = None) -> None:
        super().__init__(f"Failed to fetch {url}: {reason}")
        self.url = url
        self.status = status


def forge_headers(url: str, accept: str | None = None) -> dict[str, str]:
    """Request headers for `url`: the GitHub token goes to GitHub's API and
    raw hosts only, compared whole (core.upstream.forge_headers)."""
    return upstream_headers(url, accept, SCRAPER_AGENT)


def github_headers() -> dict[str, str]:
    """Headers for api.github.com, authenticated when a token is set.

    Anonymous calls share a quota of 60 per hour, so a scrape run after a
    few others gets 403 for every request.
    """
    return forge_headers(GITHUB_API, "application/vnd.github.v3+json")


@contextlib.contextmanager
def _fetch_errors(url: str) -> Iterator[None]:
    """Raise what a request to `url` failed with as FetchError."""
    try:
        yield
    except urllib.error.HTTPError as e:
        raise FetchError(url, e, e.code) from e
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise FetchError(url, e) from e
    except RateLimitError as e:
        raise FetchError(url, e, 429) from e
    except UpstreamError as e:
        raise FetchError(url, e) from e


def _open(
    request: urllib.request.Request,
    consume: Callable[[http.client.HTTPResponse], _T],
    timeout: float,
) -> _T:
    """Open `request` and hand the response to `consume`, retried as
    core.upstream.open_retrying does. A header the request does not set
    comes from forge_headers(). A failure raises FetchError."""
    url = request.full_url
    for name, value in forge_headers(url).items():
        if not request.has_header(name.capitalize()):
            request.add_header(name, value)
    with _fetch_errors(url):
        return open_retrying(request, consume, timeout)


def fetch_bytes(
    url: str,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 30,
    max_bytes: int = MAX_RESPONSE_SIZE,
) -> bytes:
    """GET a URL, waiting out a rate limit instead of failing the scrape.

    GitLab answers 429 after about a hundred raw-file reads, and Recalbox's
    cores live in one system.ini per system: the scrape died midway. A
    failure raises FetchError, a body over `max_bytes` ValueError. `headers`
    add to or replace forge_headers(url).
    """
    request = urllib.request.Request(url, data=data, headers=headers or {})
    return _open(request, lambda resp: read_limited(resp, max_bytes), timeout)


def fetch_text(url: str, headers: dict[str, str] | None = None) -> str:
    """GET a file as UTF-8 text, FetchError when it cannot be read."""
    return fetch_bytes(url, headers).decode("utf-8")


def fetch_present(url: str, headers: dict[str, str] | None = None) -> str | None:
    """A file's text, None when the server answers that it does not exist.

    Only a 404 says so: a 429, a 503 or a dropped connection is no answer
    and raises, else the file would be written up as absent.
    """
    try:
        return fetch_text(url, headers)
    except FetchError as e:
        if e.status == 404:
            return None
        raise


def download(
    url: str,
    destination: Path,
    headers: dict[str, str] | None = None,
    skip_existing: bool = False,
    timeout: float = 300,
) -> str:
    """Stream `url` into `destination`, whole or not at all, and return the
    response's Content-Disposition ("" when absent or when skipped).

    core.upstream.download does the work: a scratch file renamed into place,
    so a reader or an interrupted run never sees half an archive.
    `skip_existing` keeps a file already there without asking the server.
    A failure raises FetchError.
    """
    if skip_existing and destination.is_file():
        return ""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with _fetch_errors(url):
        served = upstream_download(
            url, destination, headers=headers, timeout=timeout, user_agent=SCRAPER_AGENT
        )
    return (served.get("Content-Disposition", "") if served is not None else "") or ""


class BlobMismatchError(ValueError):
    """A downloaded file is not the blob the repository listing names."""


def fetch_verified_blob(url: str, destination: Path, blob_sha: str, context: str = "") -> Path:
    """`destination`, downloaded from `url` unless the cached copy already is
    git blob `blob_sha`, and checked against it.

    The cache is addressed by content: a file already there is kept only
    while its blob sha is the one the repository lists.
    """
    if destination.is_file() and git_blob_sha(destination.read_bytes()) != blob_sha:
        destination.unlink()
    download(url, destination, skip_existing=True)
    if git_blob_sha(destination.read_bytes()) != blob_sha:
        destination.unlink()
        raise BlobMismatchError(f"{url} is not blob {blob_sha}{context}")
    return destination


def github_json(
    url: str, failure: str, timeout: float = 30, error: type[Exception] = RuntimeError
) -> Any:
    """An api.github.com answer, parsed. A request or a body that fails raises
    `error` with `failure` and the cause: a scrape never goes on without it."""
    try:
        return json.loads(fetch_bytes(url, github_headers(), timeout=timeout))
    except (ConnectionError, ValueError) as e:
        raise error(f"{failure}: {e}") from e


def github_tree(repo: str, ref: str, recursive: bool = True) -> list[dict]:
    """Every entry of a GitHub repository's tree at `ref`, the whole tree or
    its top level only."""
    url = f"{GITHUB_API}/repos/{repo}/git/trees/{ref}" + ("?recursive=1" if recursive else "")
    return tree_entries(github_json(url, f"cannot list {repo} at {ref}"), repo, ref)


def tree_entries(payload: object, repo: str, ref: str) -> list[dict]:
    """The entries of a git/trees answer, RuntimeError when it is not one or
    comes back truncated.

    A partial tree drops files without a word, and whatever is written from
    it loses them too.
    """
    entries = payload.get("tree") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or not isinstance(entries, list):
        raise RuntimeError(f"the {repo} tree at {ref} is unreadable")
    if payload.get("truncated"):
        raise RuntimeError(f"the {repo} tree at {ref} is truncated")
    return [entry for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)]


def submodule_commit(repo: str, path: str, ref: str) -> str:
    """The commit the submodule at `path` of a GitHub repository pins at `ref`.

    RuntimeError when the path is not a submodule: a directory's contents
    answer carries a sha too, the sha of a tree, which then read as a
    commit of the submodule's repository.
    """
    url = f"{GITHUB_API}/repos/{repo}/contents/{path}?ref={ref}"
    found = github_json(url, f"cannot read {path} of {repo} at {ref}")
    is_link = isinstance(found, dict) and found.get("type") == "submodule"
    sha = found.get("sha") if is_link else None
    if not isinstance(sha, str) or not sha:
        raise RuntimeError(f"{path} of {repo} at {ref} is not a submodule")
    return sha


def fetch_github_latest_version(repo: str) -> str:
    """Return the tag of the latest release of a GitHub repo.

    Raises instead of returning a fallback: a platform YAML written without
    the release it was read from cannot be patched back by the exporter.
    """
    url = f"{GITHUB_API}/repos/{repo}/releases/latest"
    release = github_json(url, f"cannot read the latest release of {repo}")
    tag = release.get("tag_name") if isinstance(release, dict) else None
    if not isinstance(tag, str) or not tag:
        raise RuntimeError(f"the latest release of {repo} names no tag")
    return tag


def json_object(raw: str) -> dict | None:
    """The text parsed as a JSON object, None when it is not one."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def systems_from_requirements(
    requirements: list[BiosRequirement],
    system_fields: Callable[[BiosRequirement], dict] | None = None,
) -> dict[str, dict]:
    """Each system's platform YAML block, its files in scrape order.

    ``system_fields`` gives the keys a system carries beside its files
    (native id, display name), read from its first requirement.
    """
    systems: dict[str, dict] = {}
    for req in requirements:
        if req.system not in systems:
            systems[req.system] = {"files": [], **(system_fields(req) if system_fields else {})}
        systems[req.system]["files"].append(requirement_entry(req))
    return systems


def optional_core_lists(
    standalone: list[str], dual: list[str], installable: list[str] | None = None
) -> dict[str, list[str]]:
    """The core lists a platform YAML writes only when they name a core:
    standalone builds, cores launched both ways (each layout gets its files),
    and cores a board can install."""
    lists = {"standalone_cores": standalone, "dual_mode_cores": dual,
             "installable_cores": installable or []}
    return {key: names for key, names in lists.items() if names}


class BaseScraper(ABC):
    """Abstract base class for platform BIOS requirement scrapers."""

    # False for a platform whose file list is inherited and whose scraper
    # reads only its core list (RetroPie). Otherwise an empty read is an
    # upstream that changed shape, never a platform with no file.
    lists_files: bool = True

    def __init__(self, url: str = "") -> None:
        self.url = url
        self._raw_data: str | None = None
        self._json_data: dict | None = None

    def _fetch_raw(self) -> str:
        """Fetch raw content from source URL. Cached after first call."""
        if self._raw_data is not None:
            return self._raw_data
        if not self.url:
            raise ValueError("No source URL configured")
        self._raw_data = fetch_bytes(self.url).decode("utf-8")
        return self._raw_data

    def _fetch_json(self) -> dict:
        """The source parsed as a JSON object. Cached after first call."""
        if self._json_data is None:
            raw = self._fetch_raw()
            try:
                self._json_data = json.loads(raw)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse JSON: {e}") from e
        return self._json_data

    @abstractmethod
    def fetch_requirements(self) -> list[BiosRequirement]:
        """Fetch current BIOS requirements from the platform source."""
        ...

    def compare_with_config(self, config: dict) -> ChangeSet:
        """Compare scraped requirements against existing platform config."""
        scraped = self.fetch_requirements()
        changes = ChangeSet()

        existing = {}
        for sys_id, system in config.get("systems", {}).items():
            for f in system.get("files", []):
                key = (sys_id, f["name"])
                existing[key] = f

        scraped_map = {}
        for req in scraped:
            key = (req.system, req.name)
            scraped_map[key] = req

        for key, req in scraped_map.items():
            if key not in existing:
                changes.added.append(req)
            else:
                existing_file = existing[key]
                if (
                    req.sha1
                    and existing_file.get("sha1")
                    and req.sha1 != existing_file["sha1"]
                ):
                    changes.modified.append(
                        (
                            BiosRequirement(
                                name=existing_file["name"],
                                system=key[0],
                                sha1=existing_file.get("sha1"),
                                md5=existing_file.get("md5"),
                            ),
                            req,
                        )
                    )
                elif (
                    req.md5
                    and existing_file.get("md5")
                    and req.md5 != existing_file["md5"]
                ):
                    changes.modified.append(
                        (
                            BiosRequirement(
                                name=existing_file["name"],
                                system=key[0],
                                md5=existing_file.get("md5"),
                            ),
                            req,
                        )
                    )

        for key in existing:
            if key not in scraped_map:
                f = existing[key]
                changes.removed.append(
                    BiosRequirement(
                        name=f["name"],
                        system=key[0],
                        sha1=f.get("sha1"),
                        md5=f.get("md5"),
                    )
                )

        return changes

    def test_connection(self) -> bool:
        """Test if the source URL is reachable."""
        try:
            self.fetch_requirements()
            return True
        except (ConnectionError, ValueError, OSError):
            return False

    @abstractmethod
    def validate_format(self, raw_data: str) -> bool:
        """Validate source data format. Returns False if format has changed unexpectedly."""
        ...


def fetch_branch_head(repo: str, branch: str | None = None) -> str:
    """The commit a branch or tag of a GitHub repo points at right now, the
    default branch when none is named.

    A platform read from a moving branch records this sha in its source URL,
    so the exporter later patches the revision the data was read from and
    not whatever the branch has become. core.upstream.resolve_head asks the
    forge and keeps no copy: the sha lives in the scraper's output. Raises
    RuntimeError like the release lookup.
    """
    owner, _, name = repo.partition("/")
    forge = make_repo("github.com", owner, name)
    ref = f"{repo}@{branch or 'default branch'}"
    if forge is None:
        raise RuntimeError(f"{ref}: not a GitHub repository")
    try:
        sha = resolve_head(forge, None, branch=branch)
    except (UpstreamError, ValueError) as e:
        raise RuntimeError(f"cannot read the head of {ref}: {e}") from e
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError(f"{ref} answered no commit sha")
    return sha


class _PlatformDumper(yaml.SafeDumper):
    """Quote scalars that a YAML reader could misparse.

    Names such as "7800 BIOS (E).rom" or "Bandai - WonderSwan: x" are plain
    text, and a bare "01" would be read back as an integer.

    Two records sharing one list are written out twice, never as an anchor
    and its alias: RetroBat's amiberry search and copy records share their
    name list, and the platform file turned into &id001 and *id001.
    """

    def ignore_aliases(self, data: object) -> bool:
        return True


def _quoted_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    style = None
    if any(c in data for c in "()[]{}:#") or data.strip() != data or data.isdigit():
        style = '"'
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_PlatformDumper.add_representer(str, _quoted_str)


def exit_on_scrape_error(error: Exception) -> NoReturn:
    """Print what failed and what to try, then exit 1 without a traceback."""
    print(f"Error: {error}", file=sys.stderr)
    refused = re.search(r"\b(403|429)\b|rate limit", str(error), re.I)
    if refused and not github_token():
        # A gh login is read on its own, so the hint is the login itself.
        print(
            "Anonymous GitHub API calls are limited to 60 an hour. "
            "Log in with `gh auth login`, or set GITHUB_TOKEN, and run again.",
            file=sys.stderr,
        )
    else:
        print("Check the network and the URL above, then run again.", file=sys.stderr)
    sys.exit(1)


def _print_dry_run(reqs: list[BiosRequirement]) -> None:
    by_system: dict[str, list] = {}
    for req in reqs:
        by_system.setdefault(req.system, []).append(req)
    for system, files in sorted(by_system.items()):
        req_count = sum(1 for f in files if f.required)
        opt_count = len(files) - req_count
        print(f"  {system}: {req_count} required, {opt_count} optional")
    print(f"\nTotal: {len(reqs)} BIOS entries across {len(by_system)} systems")


def _print_json(reqs: list[BiosRequirement]) -> None:
    data = [
        {
            "name": r.name,
            "system": r.system,
            "sha1": r.sha1,
            "md5": r.md5,
            "size": r.size,
            "required": r.required,
        }
        for r in reqs
    ]
    print(json.dumps(data, indent=2))


def _generic_config(reqs: list[BiosRequirement]) -> dict:
    """Generic fallback: just systems from requirements."""
    return {"systems": systems_from_requirements(
        reqs, lambda req: {"native_id": req.native_id} if req.native_id else {},
    )}


def _keep_existing(config: dict, output_path: Path) -> None:
    """Merge into existing YAML: preserve fields the scraper doesn't generate
    (data_directories, case_insensitive_fs, manually added metadata).
    The scraper replaces systems + files, everything else is preserved."""
    existing = source_yaml_file(output_path) or {}
    # Preserve existing keys not generated by the scraper.
    # Only keys present in the NEW config are considered scraper-generated.
    # Everything else in the existing file is preserved.
    for key, val in existing.items():
        if key not in config:
            config[key] = val
    # Preserve per-system fields not generated by the scraper
    # (data_directories, native_id from manual additions, etc.)
    existing_systems = existing.get("systems", {})
    for sys_id, sys_data in config.get("systems", {}).items():
        old_sys = existing_systems.get(sys_id, {})
        for field_name in ("data_directories",):
            if field_name in old_sys and field_name not in sys_data:
                sys_data[field_name] = old_sys[field_name]


def _write_output(
    scraper: BaseScraper, scraper_class: type, reqs: list[BiosRequirement], output: str
) -> None:
    # Use scraper's generate_platform_yaml() if available (includes
    # platform metadata, cores list, standalone_cores, etc.)
    generate = getattr(scraper, "generate_platform_yaml", None)
    if generate is not None:
        try:
            config = generate()
        except (OSError, ValueError, RuntimeError) as e:
            exit_on_scrape_error(e)
    else:
        config = _generic_config(reqs)
    if scraper.lists_files and not any(
        (system or {}).get("files") for system in (config.get("systems") or {}).values()
    ):
        exit_on_scrape_error(RuntimeError(
            f"{scraper_class.__module__}: the generated platform lists no file"
        ))
    output_path = Path(output)
    if output_path.exists():
        _keep_existing(config, output_path)
    # Written whole or not at all: a reader in the middle of a streamed
    # dump parsed a valid platform with a fraction of its systems.
    write_text_atomic(output_path, yaml.dump(
        config, Dumper=_PlatformDumper,
        default_flow_style=False, allow_unicode=True, sort_keys=False,
    ))
    print(f"Written {len(reqs)} entries to {output}")


def scraper_cli(
    scraper_class: type, description: str = "Scrape BIOS requirements"
) -> None:
    """Shared CLI entry point for all scrapers. Eliminates main() boilerplate."""
    parser = argparse.ArgumentParser(allow_abbrev=False, description=description)
    parser.add_argument("--dry-run", action="store_true", help="Show scraped data")
    parser.add_argument("--output", "-o", help="Output YAML file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    takes_revision = "revision" in inspect.signature(scraper_class).parameters
    if takes_revision:
        parser.add_argument(
            "--revision",
            help="Read this branch head or commit instead of the revision the platform file pins",
        )
    args = parser.parse_args()

    try:
        scraper = scraper_class(revision=args.revision) if takes_revision else scraper_class()
        reqs = scraper.fetch_requirements()
    except (OSError, ValueError, RuntimeError) as e:
        exit_on_scrape_error(e)
    if scraper.lists_files and not reqs:
        # Written, an empty read became a platform with no system that
        # verify and the pack count 0/0 and call consistent.
        exit_on_scrape_error(RuntimeError(
            f"{scraper_class.__module__}: upstream returned no BIOS entry"
        ))

    if args.dry_run:
        _print_dry_run(reqs)
    elif args.json:
        _print_json(reqs)
    elif args.output:
        _write_output(scraper, scraper_class, reqs, args.output)
    else:
        print(f"Scraped {len(reqs)} requirements. Use --dry-run, --json, or --output.")


def fetch_github_latest_tag(repo: str, prefix: str = "") -> str:
    """Return the most recent tag of a GitHub repo, matching `prefix` if given.

    Raises like fetch_github_latest_version: a tag that cannot be read is not
    a reason to scrape a branch under it.
    """
    url = f"{GITHUB_API}/repos/{repo}/tags?per_page=50"
    tags = github_json(url, f"cannot read the tags of {repo}")
    names = [
        tag["name"] for tag in (tags if isinstance(tags, list) else [])
        if isinstance(tag, dict) and isinstance(tag.get("name"), str)
        and tag["name"].startswith(prefix)
    ]
    if not names:
        raise RuntimeError(f"{repo} has no tag starting with {prefix!r}")
    return names[0]
