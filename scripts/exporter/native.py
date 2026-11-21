"""One platform's own BIOS file, rewritten and corrected by the ground truth.

The truth model and the platform's YAML are read, the exporter renders the
file from the platform's original, and a report lists every change."""

from __future__ import annotations

import functools
import json
from pathlib import Path

import yaml

from core.artifacts import write_bytes_atomic, write_if_changed
from core.text import count_text
from core.ziptools import build_zip_contents_index
from .base_exporter import BaseExporter
from .doubled import doubled_destinations
from .landed import LandedChanges, landed_changes
from .originals import collect_originals, unpinned, wanted_sources
from model.database import load_database
from model.platforms import load_platform_config, native_layer
from model.profiles import load_emulator_profiles
from model.registry import load_data_dir_registry, load_platform_registry
from model.safeparse import yaml_load
from resolve.categories import removal_candidates
from resolve.reconcile import Report, build_native_model
from resolve.truth import generate_platform_truth


# The database generate_truth reads by default.
TRUTH_DB = "database.json"


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


class StaleTruth(ValueError):
    """The truth file no longer describes the profiles it was built from."""


@functools.cache
def _truth_sources(platforms_dir: str) -> tuple[dict, dict, dict | None]:
    """Registry, profiles and database, as generate_truth reads them."""
    registry = load_platform_registry(platforms_dir)
    db = load_database(TRUTH_DB) if Path(TRUTH_DB).exists() else None
    return registry, _profiles(), db


def _profiles() -> dict[str, dict]:
    """The emulator profiles the truth and the exporters read."""
    return load_emulator_profiles("emulators")


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
    exporter: BaseExporter = exporter_class(_profiles())
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
        scraped, _profiles(), db, zip_contents,
        load_data_dir_registry(platforms_dir),
    )


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

    profiles = _profiles()
    exporter: BaseExporter = exporter_class(profiles)
    produced, issues, stopped = _produce(
        exporter, systems, report, scraped, upstream_dir, allow_fetch,
    )
    if stopped:
        return False, stopped

    platform_dir = output_dir / platform
    _remove_stale(platform_dir, set(produced))
    _write_produced(platform_dir, produced, exporter.file_modes())

    changes = landed_changes(exporter, systems)
    applied, filled = changes.applied, changes.filled
    resized, cleared = changes.resized, changes.cleared
    unsized = changes.unsized
    requirements = changes.requirements

    landed, refused, lost = _entry_outcomes(exporter, systems)

    own_summary = exporter.outcome(systems, produced)
    summary = own_summary
    if summary is None:
        summary = _landed_summary(report, changes, landed, lost)
    withheld = exporter.withheld()
    unwritten = _unwritten(refused, withheld, report)
    # Reported, never removed: the platform's file keeps every entry.
    candidates = removal_candidates(
        systems, scraped, profiles, load_data_dir_registry(platforms_dir),
    )
    # Reported, never rewritten: both declarations stay as the platform wrote them.
    doubled = doubled_in(scraped, platforms_dir)
    messages = _export_messages(summary, unwritten, candidates, doubled, withheld, changes)

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
        "hashes_updated": applied,
        "hashes_filled": filled,
        "sizes_updated": resized,
        "sizes_removed": unsized,
        "hashes_cleared": cleared,
        "required_aligned": requirements,
        "withheld": list(withheld),
        "found_by_content": report.labels,
        "unattributed": report.unattributed,
        "removal_candidates": candidates,
        "doubled": doubled,
        "invalid": issues,
    })
    return True, messages


def _produce(
    exporter: BaseExporter,
    systems: dict,
    report: Report,
    scraped: dict | None,
    upstream_dir: Path,
    allow_fetch: bool,
) -> tuple[dict, list[str], list[str]]:
    """The files the exporter renders, its validator's issues, and why the
    export stops before writing (empty when it goes on)."""
    off_pin = unpinned(wanted_sources(exporter, systems, scraped), scraped)
    if off_pin:
        return {}, [], off_pin
    originals, missing = collect_originals(
        exporter, systems, upstream_dir, allow_fetch, scraped
    )
    if missing:
        return {}, [], [f"the platform's own file is required: {m}" for m in missing]
    if exporter.needs_original() and not originals:
        return {}, [], ["the platform's own file is required and none was read"]

    try:
        produced = exporter.render(systems, report, originals, scraped)
    except ValueError as exc:
        return {}, [], [str(exc)]

    if not produced and not exporter.may_write_nothing():
        return {}, [], ["the exporter produced no file"]

    issues = exporter.validate(systems, produced)
    if issues:
        # Written first, a file its own validator refused replaced the
        # published export and only the exit code said so.
        invalid = [f"INVALID: {issue}" for issue in issues[:10]]
        if len(issues) > 10:
            invalid.append(f"and {len(issues) - 10} more validation failures")
        return {}, issues, invalid
    return produced, issues, []


def _entry_outcomes(exporter: BaseExporter, systems: dict) -> tuple[int, int, int]:
    """Additions written, additions refused, and platform entries lost."""
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
    return landed, refused, lost


def _landed_summary(report: Report, changes: LandedChanges, landed: int, lost: int) -> str:
    # What the written file carries, in the terms the exports page uses.
    # What it does not carry is counted on a line of its own below.
    parts = [f"{report.files_kept} kept"]
    landed_counts = (
        (landed, "file", "", "added"),
        (len(changes.applied), "hash", "", "updated to the emulator source"),
        (changes.requirements, "required flag", "", "aligned with the code"),
        (len(changes.filled), "hash", "", "added to an existing entry"),
        (len(changes.resized), "size", "", "updated to the emulator source"),
        (len(changes.unsized), "size", "", "removed"),
        (len(changes.cleared), "hash", "", "removed"),
        (lost, "entry", "entries", "removed, the format cannot state them"),
        (changes.lists, "md5 list", "", "written, any listed value passes"),
    )
    parts += [
        f"{count_text(number, noun, plural)} {verb}"
        for number, noun, plural, verb in landed_counts
        if number
    ]
    return ", ".join(parts)


def _unwritten(refused: int, withheld: list[str], report: Report) -> list[str]:
    return [
        f"{count_text(number, noun, plural)} {what}"
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


def _export_messages(
    summary: str,
    unwritten: list[str],
    candidates: list[dict],
    doubled: list[dict],
    withheld: list[str],
    changes: LandedChanges,
) -> list[str]:
    messages = [summary]
    if unwritten:
        messages.append("not in the file: " + ", ".join(unwritten))
    if candidates:
        open_question = sum(c["verdict"] == "undetermined" for c in candidates)
        messages.append(
            f"{count_text(len(candidates), 'entry', 'entries')} no examined core is known to open"
            + (f" ({open_question} undetermined)" if open_question else "")
            + ", listed in the report"
        )
    if doubled:
        messages.append(
            f"{count_text(len(doubled), 'destination')} declared twice for two files"
            ", listed in the report"
        )
    messages.extend(f"withheld: {reason}" for reason in withheld)
    for heading, labels in (
        ("hash updated", changes.applied),
        ("hash added", changes.filled),
        ("size updated", changes.resized),
        ("size removed", changes.unsized),
        ("hash removed", changes.cleared),
    ):
        messages.extend(f"{heading}: {label}" for label in labels[:5])
        if len(labels) > 5:
            messages.append(f"and {len(labels) - 5} more")
    return messages


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
