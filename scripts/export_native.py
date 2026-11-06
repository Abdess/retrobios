#!/usr/bin/env python3
"""Rewrite each platform's own BIOS file, corrected by the ground truth.

The output is the file the platform maintains, not a rendering of our data
in its syntax: what the truth can prove is applied, what it says nothing
about is left alone, and what it knows and the platform lacks is added. The
formats that carry code are patched rather than regenerated, so the checker
a platform ships keeps working.

Usage:
    python scripts/export_native.py --all --fetch           # into exports/
    python scripts/export_native.py --platform recalbox --upstream-dir up/
    python scripts/export_native.py --platform retrobat --refresh-cache
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import http.client
import re
import json
import sys
import tarfile
import urllib.request
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import file_lock, write_bytes_atomic, write_if_changed, write_text_atomic
import yaml

from common import (
    InputMissing,
    build_zip_contents_index,
    platform_arg,
    list_registered_platforms,
    load_data_dir_registry,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    load_platform_registry,
    native_layer,
    require_platform,
    yaml_load,
)
from exporter import discover_exporters
from exporter.baseline import HASH_FIELDS, _hash_values, _single_size, build_native_model
from exporter.candidates import removal_candidates
from exporter.doubled import doubled_destinations
from truth import generate_platform_truth

DEFAULT_CACHE = ".cache/upstream-native"
# The database generate_truth reads by default.
TRUTH_DB = "database.json"
SOURCES_INDEX = ".sources.json"
_USER_AGENT = "retrobios-exporter/1.0"
_MAX_BYTES = 64 * 1024 * 1024


class SourcesIndexUnreadable(InputMissing):
    """The cache's URL index exists and does not read as JSON."""


def _load_sources(index: Path | None) -> dict[str, str]:
    """The URL each cached file was fetched from.

    An absent index records nothing. An index that does not read raises:
    read as empty it let every cached original pass for current, and the
    next download rewrote it with that one entry.
    """
    if index is None or not index.is_file():
        return {}
    try:
        return json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourcesIndexUnreadable(
            f"{index} does not read ({exc}): remove it, then"
            " python scripts/export_native.py --all --refresh-cache"
            " downloads every original again and records its URL"
        ) from exc


def source_key(destination: Path, index: Path | None) -> str:
    """How the index names a cached file: its path below the cache root.

    A key that repeated the cache directory as it was typed changed with the
    working directory, and a file recorded from one place looked unrecorded
    from another.
    """
    if index is not None:
        try:
            return destination.resolve().relative_to(index.parent.resolve()).as_posix()
        except ValueError:
            pass
    return str(destination)


def load_sources(upstream_dir: Path) -> dict[str, str]:
    """Cached file -> URL it was fetched from, for a whole cache directory."""
    return _load_sources(upstream_dir / SOURCES_INDEX)


class OriginalUnreadable(ValueError):
    """A platform's file that is not what its format says it is."""


def _read_archive(unpack: Callable[[bytes], dict[str, str]], payload: bytes) -> dict[str, str]:
    """Unpack an original, naming the remedy when its bytes are not one."""
    try:
        return unpack(payload)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, zlib.error, KeyError) as exc:
        raise OriginalUnreadable(
            f"archive unreadable ({exc}): --refresh-cache downloads it again"
        ) from exc


def _read_text(payload: bytes) -> str:
    """A text original, refused when it cannot be the platform's file.

    An empty body or an HTML error page served with 200 parsed as a file
    with no entries, and four exporters rebuilt the platform's file from our
    data alone and said OK: libretro's quoted names and Recalbox's comments
    were gone.
    """
    text = payload.decode("utf-8", errors="replace")
    head = text.lstrip()[:64].lower()
    if not head:
        raise OriginalUnreadable("empty file: --refresh-cache downloads it again")
    if head.startswith(("<!doctype html", "<html")):
        raise OriginalUnreadable(
            "an HTML page, not the platform's file: --refresh-cache downloads it again"
        )
    return text


def fetch(
    url: str,
    destination: Path,
    index: Path | None = None,
    refresh: bool = False,
    check: Callable[[bytes], object] | None = None,
) -> bytes:
    """Download an original once, then read it from the cache.

    The cache path carries the file's own name and nothing of the revision it
    came from, so a file fetched under one pin was served under every later
    one and pinned_base() stopped having any effect after the first run. The
    URL that produced each cached file is recorded beside the cache, and a
    different URL refetches. A cache written before this index existed keeps
    being served: nothing recorded means nothing contradicted.

    A branch URL names no revision, so the same URL serves new bytes after
    the platform moves. refresh downloads again whatever the cache holds:
    it is what a rescrape calls, so the original and its transcription
    describe the same moment.
    """
    key = source_key(destination, index)

    def locked() -> contextlib.AbstractContextManager[object]:
        # The bytes and the URL that names them change together: written
        # under two locks, two runs wanting two URLs for one path could leave
        # one's bytes beside the other's index entry, and the wrong revision
        # was then served as current.
        if index is None:
            return contextlib.nullcontext()
        index.parent.mkdir(parents=True, exist_ok=True)
        return file_lock(index.with_name(f".{index.name}.lock"))

    with locked():
        if (
            not refresh
            and destination.exists()
            and _load_sources(index).get(key, url) == url
        ):
            return destination.read_bytes()
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(_MAX_BYTES + 1)
    if len(payload) > _MAX_BYTES:
        raise OriginalUnreadable(f"{url}: response larger than {_MAX_BYTES} bytes")
    # An error page served with 200 replaced a good archive and was then
    # served on every run: what does not read is never cached.
    if check is not None:
        check(payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with locked():
        write_bytes_atomic(str(destination), payload)
        if index is not None:
            # Platforms refresh in parallel: the index is read again under
            # the lock, or the last writer erased what the others recorded.
            recorded = _load_sources(index)
            recorded[key] = url
            write_text_atomic(
                str(index), json.dumps(recorded, indent=2, sort_keys=True) + "\n"
            )
    return payload


def _remove_stale(platform_dir: Path, produced: set[str]) -> None:
    """Remove what an earlier run wrote and this one does not.

    RetroPie writes one scriptmodule per package it corrects and RetroDECK one
    manifest per component: a package corrected by an older truth kept its
    file beside a report saying it was no longer touched, and the directory
    contradicted the run.
    """
    if not platform_dir.is_dir():
        return
    for path in sorted(platform_dir.rglob("*"), reverse=True):
        relative = path.relative_to(platform_dir).as_posix()
        if path.is_file() and relative not in produced:
            path.unlink()
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()


def pinned_base(wanted: dict[str, str], scraped: dict | None) -> str:
    """The revision our transcription came from, when the YAML records it.

    A scraper pins a stable tag (batocera-43.1, BizHawk 2.11.1) and writes
    that URL into the platform YAML. Patching the branch tip instead would
    correct a file our data never described.
    """
    source = _raw_url(str((scraped or {}).get("source", "")))
    tree = _GITHUB_TREE.match(source)
    if tree:
        # RetroDECK reads one manifest per component: the YAML records the
        # tree at the commit read, and every file is taken at that commit.
        return "https://raw.githubusercontent.com/{}/{}/{}/".format(*tree.groups())
    for relative in wanted:
        if source.endswith("/" + relative):
            return source[: -len(relative)]
    return ""


_GITHUB_TREE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/tree/([0-9a-f]{40})/?$")


def _raw_url(url: str) -> str:
    """A GitHub blob page names a revision but serves HTML, raw serves bytes."""
    marker = "/blob/"
    if url.startswith("https://github.com/") and marker in url:
        owner_repo, _, path = url[len("https://github.com/") :].partition(marker)
        return f"https://raw.githubusercontent.com/{owner_repo}/{path}"
    return url


def wanted_sources(
    exporter: object, systems: dict, scraped: dict | None = None
) -> dict[str, str]:
    """Cache-relative name -> URL of every file the exporter patches."""
    wanted = dict(exporter.native_sources())
    components = getattr(exporter, "components", None)
    if callable(components):
        for component in components(systems):
            wanted[f"{component}/component_manifest.json"] = exporter.component_url(
                component
            )

    base = pinned_base(wanted, scraped)
    if base:
        wanted = {
            relative: _at_revision(wanted[relative], base) or base + relative
            for relative in wanted
        }
    source = str((scraped or {}).get("source", ""))
    return {
        relative: _tarball_at(url, source) or url for relative, url in wanted.items()
    }


_REVISION = (
    re.compile(r"^https://raw\.githubusercontent\.com/[^/]+/[^/]+/([^/]+)/"),
    re.compile(r"^https://github\.com/[^/]+/[^/]+/(?:tree|blob)/([^/]+)"),
    re.compile(r"^https://gitlab\.com/.+?/-/(?:raw|archive)/([^/]+)/"),
    re.compile(r"^https://codeload\.github\.com/[^/]+/[^/]+/tar\.gz/([^/]+)$"),
)


def source_revision(source: str) -> str:
    """The revision a platform YAML's source: URL names, '' when none."""
    for pattern in _REVISION:
        match = pattern.match(source)
        if match:
            return match.group(1)
    return ""


def unpinned(wanted: dict[str, str], scraped: dict | None) -> list[str]:
    """Every file the export would read off the revision the YAML records.

    pinned_base() returned '' when the source named no revision or no
    longer ended in the file, and the exporter's own branch URL was then
    patched without a word: a file our transcription never described.
    """
    source = str((scraped or {}).get("source", ""))
    revision = source_revision(source)
    if not revision:
        return [f"the platform's source names no revision ({source or 'none'}): rescrape it"]
    return [
        f"{relative} would be read at {url}, not at {revision}: rescrape the platform"
        for relative, url in wanted.items()
        if f"/{revision}/" not in url and not url.endswith(f"/{revision}")
    ]


_CODELOAD = re.compile(r"^https://codeload\.github\.com/([^/]+)/([^/]+)/tar\.gz/")


def _tarball_at(url: str, source: str) -> str:
    """The recorded tarball when the original is a tarball of the same repository.

    RetroPie's declarations are spread over every scriptmodule, so its scraper
    reads the repository archive. The archive the YAML records is the one at
    the commit it was read from, the exporter's own URL names the branch.
    """
    wanted, recorded = _CODELOAD.match(url), _CODELOAD.match(source)
    if wanted and recorded and wanted.group(1, 2) == recorded.group(1, 2):
        return source
    return ""


_RAW_GITHUB = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/")


def _at_revision(url: str, base: str) -> str:
    """A file of the pinned repository, read at the pinned revision, empty
    when the URL is not a raw GitHub URL of that repository.

    ROCKNIX's checker sits in packages/rocknix/, the emulators it names in
    packages/virtual/: no shared directory, one revision.
    """
    pinned, other = _RAW_GITHUB.match(base), _RAW_GITHUB.match(url)
    if pinned and other and pinned.group(1, 2) == other.group(1, 2):
        return pinned.group(0) + url[other.end():]
    return ""


def collect_originals(
    exporter: object,
    systems: dict,
    upstream_dir: Path,
    allow_fetch: bool,
    scraped: dict | None = None,
    refresh: bool = False,
) -> tuple[dict[str, str], list[str]]:
    """Gather the platform's own files, from disk or from upstream.

    With fetching on, an existing file still goes through fetch(): reading
    it straight from disk skipped the recorded URL, so a file cached under
    one pin kept being patched after the platform YAML moved to the next.
    """
    wanted = wanted_sources(exporter, systems, scraped)
    root = upstream_dir / exporter.platform_name()
    index = upstream_dir / SOURCES_INDEX
    originals: dict[str, str] = {}
    missing: list[str] = []
    unpack = getattr(exporter, "unpack", None)
    for relative, url in wanted.items():
        path = root / relative
        archive = callable(unpack) and relative.endswith((".zip", ".tar.gz"))
        check = (lambda raw: _read_archive(unpack, raw)) if archive else _read_text
        try:
            if allow_fetch:
                payload = fetch(url, path, index, refresh, check)
            elif path.exists():
                payload = path.read_bytes()
            else:
                missing.append(
                    f"{relative}: not in {root}; rerun with --fetch to download it"
                )
                continue
            if archive:
                originals.update(_read_archive(unpack, payload))
                keep = getattr(exporter, "keep_archive", None)
                if callable(keep):
                    keep(relative, payload)
            else:
                originals[relative] = _read_text(payload)
        # One platform's unreadable file fails that platform: raised, it
        # stopped --all before the platforms after it.
        except (OSError, http.client.HTTPException, OriginalUnreadable) as exc:
            missing.append(f"{relative}: {exc}")

    return originals, missing


class StaleTruth(ValueError):
    """The truth file no longer describes the profiles it was built from."""


@functools.lru_cache(maxsize=None)
def _truth_sources(platforms_dir: str) -> tuple[dict, dict, dict | None]:
    """Registry, profiles and database, as generate_truth reads them."""
    registry_path = Path(platforms_dir) / "_registry.yml"
    registry: dict = {}
    if registry_path.exists():
        with open(registry_path) as handle:
            registry = (yaml_load(handle) or {}).get("platforms", {})
    profiles = load_emulator_profiles("emulators")
    db = load_database(TRUTH_DB) if Path(TRUTH_DB).exists() else None
    return registry, profiles, db


def current_truth(platform: str, config: dict, platforms_dir: str) -> dict:
    """The truth model generate_truth would write now, as YAML reads it back."""
    registry, profiles, db = _truth_sources(platforms_dir)
    model = generate_platform_truth(
        platform, config, registry.get(platform, {}), profiles, db=db,
        data_registry=load_data_dir_registry(platforms_dir),
    )
    return yaml_load(yaml.dump(model, default_flow_style=False, sort_keys=False,
                               allow_unicode=True)) or {}


def load_inputs(
    platform: str, truth_dir: Path, platforms_dir: str
) -> tuple[dict | None, dict | None]:
    """The truth and the scraped config of a platform, None where absent.

    A truth file is an artifact of the profiles: read at any age, one from
    before `_required_by` existed silently undid the RetroPie guard that
    reads it. One that no longer matches what generate_truth builds now is
    refused.
    """
    truth_file = truth_dir / f"{platform}.yml"
    truth: dict | None = None
    try:
        config = load_platform_config(platform, platforms_dir)
    except (FileNotFoundError, OSError):
        config = None
    if truth_file.exists():
        with open(truth_file) as handle:
            truth = yaml_load(handle) or {}
        if config is not None and truth != current_truth(platform, config, platforms_dir):
            raise StaleTruth(
                f"{truth_file} no longer matches the profiles: run "
                f"python scripts/generate_truth.py --platform {platform}"
            )
    return truth, native_layer(config)


def refresh_cache(
    platform: str,
    exporter_class: type,
    truth_dir: Path,
    platforms_dir: str,
    upstream_dir: Path,
) -> tuple[bool, list[str]]:
    """Download a platform's own files again. Returns (ok, messages)."""
    try:
        truth, scraped = load_inputs(platform, truth_dir, platforms_dir)
    except StaleTruth as exc:
        return False, [str(exc)]
    systems, _ = build_native_model(truth or {}, scraped)
    exporter = exporter_class()
    wanted = wanted_sources(exporter, systems, scraped)
    off_pin = unpinned(wanted, scraped)
    if off_pin:
        return False, off_pin
    _, missing = collect_originals(
        exporter, systems, upstream_dir, True, scraped, refresh=True
    )
    if missing:
        return False, missing
    return True, [f"{len(wanted)} file(s) fetched"]


@functools.cache
def _collection(db_path: str) -> tuple[dict, dict]:
    """The database and its archive index, read once for every platform."""
    db = load_database(db_path)
    return db, build_zip_contents_index(db)


def doubled_in(scraped: dict | None, platforms_dir: str) -> list[dict]:
    """The destinations the platform's own list declares for two files."""
    if not scraped:
        return []
    db, zip_contents = _collection(TRUTH_DB)
    return doubled_destinations(
        scraped, load_emulator_profiles("emulators"), db, zip_contents,
        load_data_dir_registry(platforms_dir),
    )


def _count(number: int, noun: str, plural: str = "") -> str:
    """"1 hash", "2 hashes": a count with its noun in the right number."""
    plural = plural or noun + ("es" if noun.endswith(("sh", "ch", "s", "x")) else "s")
    return f"{number} {noun if number == 1 else plural}"


@dataclass
class LandedChanges:
    """What an export changed in the platform's file, field by field.

    `records` holds each change with its value before and after, so a
    maintainer can check it against the diff. The lists of labels are read
    from it, for the summary and the page.
    """

    records: list[dict] = field(default_factory=list)

    def _labels(self, kind: str) -> list[str]:
        return [
            f"{r['system']}/{r['name']} {r['field']}"
            for r in self.records if r["kind"] == kind
        ]

    @property
    def applied(self) -> list[str]:
        return self._labels("hash_corrected")

    @property
    def filled(self) -> list[str]:
        return self._labels("hash_filled")

    @property
    def cleared(self) -> list[str]:
        return self._labels("hash_cleared")

    @property
    def resized(self) -> list[str]:
        return [label.removesuffix(" size") for label in self._labels("size_corrected")]

    @property
    def unsized(self) -> list[str]:
        return [label.removesuffix(" size") for label in self._labels("size_removed")]

    @property
    def requirements(self) -> int:
        return sum(r["kind"] == "requirement_corrected" for r in self.records)

    @property
    def lists(self) -> int:
        """Entries whose md5 is written as a list of accepted values."""
        return sum(
            isinstance(r["new"], list)
            or (isinstance(r["new"], dict) and isinstance(r["new"].get("md5"), list))
            for r in self.records
        )


def _change(
    kind: str, entry: object, field_name: str | None, old: object, new: object
) -> dict:
    return {
        "kind": kind,
        "system": entry.native_system,
        "name": entry.name,
        "destination": entry.destination,
        "field": field_name,
        "old": old,
        "new": new,
    }


def _platform_value(entry: object, field_name: str) -> str | list[str]:
    values = _hash_values(entry.platform or {}, field_name)
    if (entry.platform or {}).get(f"{field_name}_list"):
        return values
    return ",".join(values)


def _written_value(exporter: object, entry: object, field_name: str) -> str | list[str]:
    """A hash field as the render writes it: a list where the checker reads
    one, so the report never shows several values as one."""
    listed = exporter.written_list(entry, field_name)
    return listed if listed is not None else exporter.written(entry, field_name)


def _added_fields(exporter: object, entry: object) -> dict:
    """The fields an addition is written with, as the render chooses them."""
    carried = exporter.carries()
    written: dict[str, object] = {
        name: value
        for name in HASH_FIELDS
        if name in carried and (value := _written_value(exporter, entry, name))
    }
    if "size" in carried and entry.size() is not None:
        written["size"] = entry.size()
    if "required" in carried:
        written["required"] = exporter.required_value(entry)
    return written


def landed_changes(exporter: object, systems: dict) -> LandedChanges:
    """The changes the written file carries, with their values.

    Only what the format states: a correction to a field the file has no
    place for, or one its render keeps out, is not a change the maintainer
    will find in the diff, and counting it would announce work the export
    did not do. A hash written where the platform left none changes the
    check from existence to content, so it is counted too. The truth taking
    over an entry also rewrites its size and drops the platform's hashes it
    does not declare: both are in the diff. An addition carries the fields
    it is written with as its new value.
    """
    changes = LandedChanges()
    records = changes.records
    for system in systems.values():
        for entry in system.files:
            if entry.platform is None:
                if entry.name and exporter.lands(entry):
                    records.append(_change(
                        "added", entry, None, None, _added_fields(exporter, entry)
                    ))
                continue
            if entry.name and exporter.names_anew(entry):
                records.append(_change(
                    "added", entry, None, None, _added_fields(exporter, entry)
                ))
            # Asked of the exporter: a format that names each entry's cores
            # reads every entry of those cores, not only the paired one.
            if (
                entry.platform.get("required") is not None
                and exporter.states(entry, "required")
                and exporter.required_value(entry) != bool(entry.platform["required"])
            ):
                records.append(_change(
                    "requirement_corrected", entry, "required",
                    bool(entry.platform["required"]), exporter.required_value(entry),
                ))
            for field_name in entry.corrections:
                if field_name == "required" or not exporter.states(entry, field_name):
                    continue
                records.append(_change(
                    "hash_corrected", entry, field_name,
                    _platform_value(entry, field_name),
                    _written_value(exporter, entry, field_name),
                ))
            # A list the truth extends with values the platform's own lacks:
            # no contradiction, so no correction in the model, and still a
            # new value in the file.
            for field_name in HASH_FIELDS:
                listed = exporter.written_list(entry, field_name)
                if (
                    listed is not None
                    and field_name not in entry.corrections
                    and field_name not in entry.filled
                    and listed != _hash_values(entry.platform, field_name)
                    and exporter.states(entry, field_name)
                ):
                    records.append(_change(
                        "hash_corrected", entry, field_name,
                        _platform_value(entry, field_name), listed,
                    ))
            records.extend(
                _change("hash_filled", entry, field_name, None,
                        _written_value(exporter, entry, field_name))
                for field_name in entry.filled
                if exporter.fills(entry, field_name)
            )
            theirs = entry.platform.get("size")
            ours = entry.size()
            if (
                theirs
                and ours
                and _single_size(theirs) not in (None, ours)
                and exporter.states(entry, "size")
            ):
                records.append(_change(
                    "size_corrected", entry, "size", _single_size(theirs), ours
                ))
            elif (
                theirs
                and ours is None
                and _single_size(theirs) is not None
                and exporter.states(entry, "size")
            ):
                # The truth took the entry over without a size of its own:
                # System.dat's neocdz.zip line went out without size 953078.
                records.append(_change(
                    "size_removed", entry, "size", _single_size(theirs), None
                ))
            records.extend(
                _change("hash_cleared", entry, field_name,
                        _platform_value(entry, field_name), None)
                for field_name in HASH_FIELDS
                if _hash_values(entry.platform, field_name)
                and not entry.hashes(field_name)
                and exporter.clears(entry, field_name)
            )
    # A value the render rewrote though the model reads it as the
    # platform's own (RomM's sha1 with a leading space).
    records.extend(
        _change("hash_corrected", entry, field_name, old, new)
        for entry, field_name, old, new in getattr(exporter, "normalized_values", [])
    )
    return changes


def export_platform(
    platform: str,
    exporter_class: type,
    truth_dir: Path,
    output_dir: Path,
    platforms_dir: str,
    upstream_dir: Path,
    allow_fetch: bool,
) -> tuple[bool, list[str]]:
    """Write one platform's corrected file. Returns (ok, messages)."""
    messages: list[str] = []

    try:
        truth, scraped = load_inputs(platform, truth_dir, platforms_dir)
    except StaleTruth as exc:
        return False, [str(exc)]
    if truth is None:
        # Without a truth the export is the platform's file copied back, and
        # it replaced the corrected one in exports/ on a fresh clone.
        return False, [
            f"{truth_dir / f'{platform}.yml'} is absent: run "
            f"python scripts/generate_truth.py --platform {platform}"
        ]

    systems, report = build_native_model(truth, scraped)
    if not systems:
        return False, ["nothing to write: neither the platform nor the truth has data"]

    exporter = exporter_class()
    off_pin = unpinned(wanted_sources(exporter, systems, scraped), scraped)
    if off_pin:
        return False, off_pin
    originals, missing = collect_originals(
        exporter, systems, upstream_dir, allow_fetch, scraped
    )
    if missing:
        return False, [f"the platform's own file is required: {m}" for m in missing]
    if exporter.needs_original() and not originals:
        return False, ["the platform's own file is required and none was read"]

    try:
        produced = exporter.render(systems, report, originals, scraped)
    except ValueError as exc:
        return False, [str(exc)]

    if not produced and not exporter.may_write_nothing():
        return False, ["the exporter produced no file"]

    issues = exporter.validate(systems, produced)
    if issues:
        # Written first, a file its own validator refused replaced the
        # published export and only the exit code said so.
        invalid = [f"INVALID: {issue}" for issue in issues[:10]]
        if len(issues) > 10:
            invalid.append(f"and {len(issues) - 10} more validation failures")
        return False, invalid

    platform_dir = output_dir / platform
    _remove_stale(platform_dir, set(produced))
    _write_produced(platform_dir, produced, exporter.file_modes())

    changes = landed_changes(exporter, systems)
    applied, filled = changes.applied, changes.filled
    resized, cleared = changes.resized, changes.cleared
    unsized = changes.unsized
    requirements = changes.requirements
    lists = changes.lists

    landed = 0
    refused = 0
    lost = 0
    for system in systems.values():
        for entry in system.files:
            if not entry.name:
                continue
            if exporter.lands(entry):
                landed += entry.platform is None
            elif entry.platform is None:
                refused += 1
            else:
                # The platform declares it and the format still cannot state
                # it, so their own file loses a line. Worth saying out loud.
                lost += 1

    own_summary = exporter.outcome(systems, produced)
    summary = own_summary
    if summary is None:
        # What the written file carries, in the terms the exports page uses.
        # What it does not carry is counted on a line of its own below.
        parts = [f"{report.files_kept} kept"]
        landed_counts = (
            (landed, "file", "", "added"),
            (len(applied), "hash", "", "updated to the emulator source"),
            (requirements, "required flag", "", "aligned with the code"),
            (len(filled), "hash", "", "added to an existing entry"),
            (len(resized), "size", "", "updated to the emulator source"),
            (len(unsized), "size", "", "removed"),
            (len(cleared), "hash", "", "removed"),
            (lost, "entry", "entries", "removed, the format cannot state them"),
            (lists, "md5 list", "", "written, any listed value passes"),
        )
        parts += [
            f"{_count(number, noun, plural)} {verb}"
            for number, noun, plural, verb in landed_counts
            if number
        ]
        summary = ", ".join(parts)
    withheld = exporter.withheld()
    unwritten = [
        f"{_count(number, noun, plural)} {what}"
        for number, noun, plural, what in (
            (refused, "file", "", "the format or its checker cannot carry"),
            (len(withheld), "update", "", "withheld"),
            # A content-scanning core's names are labels: a list checked
            # by path cannot hold them.
            (report.labels, "entry", "entries", "found by content"),
            (len(report.unattributed), "file", "",
             "no single native system of the platform takes"),
        )
        if number
    ]
    # Reported, never removed: the platform's file keeps every entry.
    candidates = removal_candidates(
        systems, scraped, load_emulator_profiles("emulators"),
        load_data_dir_registry(platforms_dir),
    )
    # Reported, never rewritten: both declarations stay as the platform wrote them.
    doubled = doubled_in(scraped, platforms_dir)
    messages.append(summary)
    if unwritten:
        messages.append("not in the file: " + ", ".join(unwritten))
    if candidates:
        open_question = sum(c["verdict"] == "undetermined" for c in candidates)
        messages.append(
            f"{_count(len(candidates), 'entry', 'entries')} no examined core is known to open"
            + (f" ({open_question} undetermined)" if open_question else "")
            + ", listed in the report"
        )
    if doubled:
        messages.append(
            f"{_count(len(doubled), 'destination')} declared twice for two files"
            ", listed in the report"
        )
    messages.extend(f"withheld: {reason}" for reason in withheld)
    for heading, labels in (
        ("hash updated", applied),
        ("hash added", filled),
        ("size updated", resized),
        ("size removed", unsized),
        ("hash removed", cleared),
    ):
        messages.extend(f"{heading}: {label}" for label in labels[:5])
        if len(labels) > 5:
            messages.append(f"and {len(labels) - 5} more")

    write_report(output_dir / f"{platform}.json", {
        "platform": platform,
        "originals": wanted_sources(exporter, systems, scraped),
        "files": sorted(produced),
        "summary": summary,
        "counts": None if own_summary is not None else {
            "kept": report.files_kept,
            "added": landed,
            "not_added": refused,
            "not_kept": lost,
        },
        "changes": changes.records,
        "hashes_corrected": applied,
        "hashes_filled": filled,
        "sizes_corrected": resized,
        "sizes_removed": unsized,
        "hashes_cleared": cleared,
        "requirements_corrected": requirements,
        "withheld": list(withheld),
        "found_by_content": report.labels,
        "unattributed": report.unattributed,
        "removal_candidates": candidates,
        "doubled": doubled,
        "invalid": issues,
    })
    return True, messages


def _write_produced(
    root: Path, produced: dict[str, str | bytes], modes: dict[str, int]
) -> None:
    """Write each file as its bytes, whole or not at all, with its mode.

    write_text translated line ends on Windows, so FirmwareDatabase.cs's
    CRLF would have come out CR CR LF, and a run stopped mid-write left a
    truncated file in exports/. The scratch file mkstemp makes is 0600: the
    mode is set from what the platform's own file has.
    """
    for relative, content in produced.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content if isinstance(content, bytes) else content.encode("utf-8")
        write_bytes_atomic(str(path), data)
        path.chmod(modes.get(relative, 0o644))


def write_report(path: Path, report: dict) -> None:
    """What one platform's export changed, for the page that publishes it.

    The run prints five examples per kind of change. The page lists them
    all, so the maintainer reading it finds each line of the diff named.
    A platform with nothing to write made no directory of its own: the
    output directory itself may not exist yet.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(str(path), json.dumps(report, indent=2) + "\n")


def run(
    platforms: list[str],
    truth_dir: str,
    output_dir: str,
    platforms_dir: str,
    upstream_dir: str,
    allow_fetch: bool,
    refresh_only: bool = False,
) -> int:
    exporters = discover_exporters()
    registry = load_platform_registry(platforms_dir)
    failures = 0
    skipped: list[str] = []

    for platform in sorted(platforms):
        exporter_class = exporters.get(platform)
        if not exporter_class and (registry.get(platform) or {}).get("native_list") == "none":
            # The platform's code names no BIOS file: there is no list of its
            # own to hand back corrected.
            print(f"  SKIP {platform}: names no BIOS file of its own (native_list: none)")
            continue
        if not exporter_class:
            skipped.append(platform)
            print(f"  SKIP {platform}: no exporter")
            continue

        if refresh_only:
            ok, messages = refresh_cache(
                platform,
                exporter_class,
                Path(truth_dir),
                platforms_dir,
                Path(upstream_dir),
            )
        else:
            ok, messages = export_platform(
                platform,
                exporter_class,
                Path(truth_dir),
                Path(output_dir),
                platforms_dir,
                Path(upstream_dir),
                allow_fetch,
            )
        label = "OK  " if ok else "FAIL"
        print(f"  {label} {platform}")
        for message in messages:
            print(f"       {message}")
        if not ok:
            failures += 1

    if skipped:
        print(f"\n{len(skipped)} platform(s) without an exporter: {', '.join(skipped)}")
        failures += len(skipped)

    return 1 if failures else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Rewrite each platform's own BIOS file, corrected.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="every platform")
    group.add_argument("--platform", "-p", type=platform_arg, help="a single platform")
    parser.add_argument(
        "--output-dir", default="exports",
        help="directory the updated platform files go to (default: %(default)s)",
    )
    parser.add_argument(
        "--truth-dir", default="dist/truth",
        help="directory of the truth models generate_truth writes (default: "
             "%(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--upstream-dir",
        default=DEFAULT_CACHE,
        help="where the platforms' own files are read and cached",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="download a platform's file when it is not in the cache, "
        "or when the cache came from another URL",
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="download every platform file again and write no export",
    )
    args = parser.parse_args()

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir,
        )
    else:
        require_platform(args.platform, args.platforms_dir)
        platforms = [args.platform]

    if not args.refresh_cache:
        import contextlib

        from refresh_data_dirs import hold_data_dirs

        # Removal candidates are proved against data/: a refresh swapping a
        # tree mid-walk listed entries only that tree holds as removable.
        # The process exit releases the hold.
        held = contextlib.ExitStack()
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))

    sys.exit(
        run(
            platforms,
            args.truth_dir,
            args.output_dir,
            args.platforms_dir,
            args.upstream_dir,
            args.fetch,
            args.refresh_cache,
        )
    )


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
