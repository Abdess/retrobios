"""Base scraper interface for platform BIOS requirement sources."""

from __future__ import annotations

import inspect
import json
import re
import sys
import time
import urllib.error
import urllib.request

import yaml
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, NoReturn

from common import github_token, write_text_atomic, yaml_load


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


MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50 MB


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


def _read_limited(resp: object, max_bytes: int = MAX_RESPONSE_SIZE) -> bytes:
    """Read an HTTP response with a size limit to prevent OOM."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read(65536)  # type: ignore[union-attr]
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"Response exceeds {max_bytes} byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


# Statuses a forge answers when it asks the client to slow down.
_RETRYABLE = frozenset({429, 502, 503, 504})


def fetch_bytes(
    url: str,
    headers: dict[str, str] | None = None,
    attempts: int = 5,
    sleep: Callable[[float], None] = time.sleep,
    data: bytes | None = None,
) -> bytes:
    """GET a URL, waiting out a rate limit instead of failing the scrape.

    GitLab answers 429 after about a hundred raw-file reads, and Recalbox's
    cores live in one system.ini per system: the scrape died midway. The
    wait is the server's Retry-After when it gives one, else 2, 4, 8, 16 s.
    """
    request = urllib.request.Request(
        url, data=data, headers={"User-Agent": "retrobios-scraper/1.0", **(headers or {})}
    )
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return _read_limited(resp)
        except urllib.error.HTTPError as e:
            if e.code not in _RETRYABLE or attempt == attempts - 1:
                raise ConnectionError(f"Failed to fetch {url}: {e}") from e
            retry_after = e.headers.get("Retry-After", "") if e.headers else ""
            delay = float(retry_after) if retry_after.isdigit() else 2.0 ** (attempt + 1)
            sleep(min(delay, 120.0))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {url}: {e}") from e
    raise AssertionError("unreachable")


class BaseScraper(ABC):
    """Abstract base class for platform BIOS requirement scrapers."""

    # False for a platform whose file list is inherited and whose scraper
    # reads only its core list (RetroPie). Otherwise an empty read is an
    # upstream that changed shape, never a platform with no file.
    lists_files: bool = True

    def __init__(self, url: str = "") -> None:
        self.url = url
        self._raw_data: str | None = None

    def _fetch_raw(self) -> str:
        """Fetch raw content from source URL. Cached after first call."""
        if self._raw_data is not None:
            return self._raw_data
        if not self.url:
            raise ValueError("No source URL configured")
        self._raw_data = fetch_bytes(self.url).decode("utf-8")
        return self._raw_data

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


def github_headers() -> dict[str, str]:
    """Headers for api.github.com, authenticated when a token is set.

    Anonymous calls share a quota of 60 per hour, so a scrape run after a
    few others gets 403 for every request.
    """
    headers = {
        "User-Agent": "retrobios-scraper/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    # GITHUB_TOKEN, else the token gh is logged in with.
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_github_latest_version(repo: str) -> str:
    """Return the tag of the latest release of a GitHub repo.

    Raises instead of returning a fallback: a platform YAML written without
    the release it was read from cannot be patched back by the exporter.
    """
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(url, headers=github_headers())
        with urllib.request.urlopen(req, timeout=15) as resp:
            tag = json.loads(resp.read()).get("tag_name", "")
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        raise RuntimeError(f"cannot read the latest release of {repo}: {e}") from e
    if not tag:
        raise RuntimeError(f"the latest release of {repo} names no tag")
    return tag


def fetch_branch_head(repo: str, branch: str) -> str:
    """The commit a branch of a GitHub repo points at right now.

    A platform read from a moving branch records this sha in its source URL,
    so the exporter later patches the revision the data was read from and
    not whatever the branch has become. Raises like the release lookup.
    """
    url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    try:
        req = urllib.request.Request(url, headers=github_headers())
        with urllib.request.urlopen(req, timeout=15) as resp:
            sha = json.loads(resp.read()).get("sha", "")
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        raise RuntimeError(f"cannot read the head of {repo}@{branch}: {e}") from e
    if not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
        raise RuntimeError(f"{repo}@{branch} answered no commit sha")
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


def _exit_on_scrape_error(error: Exception) -> NoReturn:
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


def scraper_cli(
    scraper_class: type, description: str = "Scrape BIOS requirements"
) -> None:
    """Shared CLI entry point for all scrapers. Eliminates main() boilerplate."""
    import argparse

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
        _exit_on_scrape_error(e)
    if scraper.lists_files and not reqs:
        # Written, an empty read became a platform with no system that
        # verify and the pack count 0/0 and call consistent.
        _exit_on_scrape_error(RuntimeError(
            f"{scraper_class.__module__}: upstream returned no BIOS entry"
        ))

    if args.dry_run:
        by_system: dict[str, list] = {}
        for req in reqs:
            by_system.setdefault(req.system, []).append(req)
        for system, files in sorted(by_system.items()):
            req_count = sum(1 for f in files if f.required)
            opt_count = len(files) - req_count
            print(f"  {system}: {req_count} required, {opt_count} optional")
        print(f"\nTotal: {len(reqs)} BIOS entries across {len(by_system)} systems")
        return

    if args.json:
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
        return

    if args.output:
        import yaml

        # Use scraper's generate_platform_yaml() if available (includes
        # platform metadata, cores list, standalone_cores, etc.)
        if hasattr(scraper, "generate_platform_yaml"):
            try:
                config = scraper.generate_platform_yaml()
            except (OSError, ValueError, RuntimeError) as e:
                _exit_on_scrape_error(e)
        else:
            # Generic fallback: just systems from requirements
            config = {"systems": {}}
            for req in reqs:
                sys_id = req.system
                if sys_id not in config["systems"]:
                    sys_entry: dict = {"files": []}
                    if req.native_id:
                        sys_entry["native_id"] = req.native_id
                    config["systems"][sys_id] = sys_entry
                entry = {
                    "name": req.name,
                    "destination": req.destination or req.name,
                    "required": req.required,
                }
                if req.sha1:
                    entry["sha1"] = req.sha1
                if req.md5:
                    entry["md5"] = req.md5
                if req.zipped_file:
                    entry["zipped_file"] = req.zipped_file
                config["systems"][sys_id]["files"].append(entry)
        if scraper.lists_files and not any(
            (system or {}).get("files") for system in (config.get("systems") or {}).values()
        ):
            _exit_on_scrape_error(RuntimeError(
                f"{scraper_class.__module__}: the generated platform lists no file"
            ))
        # Merge into existing YAML: preserve fields the scraper doesn't generate
        # (data_directories, case_insensitive_fs, manually added metadata).
        # The scraper replaces systems + files, everything else is preserved.
        output_path = Path(args.output)
        if output_path.exists():
            with open(output_path) as f:
                existing = yaml_load(f) or {}
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
                for field in ("data_directories",):
                    if field in old_sys and field not in sys_data:
                        sys_data[field] = old_sys[field]
        # Written whole or not at all: a reader in the middle of a streamed
        # dump parsed a valid platform with a fraction of its systems.
        write_text_atomic(output_path, yaml.dump(
            config, Dumper=_PlatformDumper,
            default_flow_style=False, allow_unicode=True, sort_keys=False,
        ))
        print(f"Written {len(reqs)} entries to {args.output}")
        return

    print(f"Scraped {len(reqs)} requirements. Use --dry-run, --json, or --output.")


def fetch_github_latest_tag(repo: str, prefix: str = "") -> str:
    """Return the most recent tag of a GitHub repo, matching `prefix` if given.

    Raises like fetch_github_latest_version: a tag that cannot be read is not
    a reason to scrape a branch under it.
    """
    url = f"https://api.github.com/repos/{repo}/tags?per_page=50"
    try:
        req = urllib.request.Request(url, headers=github_headers())
        with urllib.request.urlopen(req, timeout=15) as resp:
            tags = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        raise RuntimeError(f"cannot read the tags of {repo}: {e}") from e
    names = [tag["name"] for tag in tags if tag["name"].startswith(prefix)]
    if not names:
        raise RuntimeError(f"{repo} has no tag starting with {prefix!r}")
    return names[0]
