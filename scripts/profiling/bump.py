"""Advancing a profile's pin, with the version it states read again at the new pin."""

from __future__ import annotations

import functools
import os
import re
from dataclasses import dataclass
from pathlib import Path

from core.paths import PLATFORMS_DIR
import yaml

from core import upstream
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.registry import list_registered_platforms
from profiling import version_basis
from profiling.anchoring import REVIEW_STATUSES
from profiling.rebase import pending_recale
from profiling.reports import ProfileReport, SkipKind
from profiling.yamledit import apply_edit, insert_after_line, replace_field_line, set_version_fields
from resolve.cores import resolve_platform_cores


DEFAULT_CACHE = upstream.CACHE_DIR


def apply_readings(document: dict, readings: list) -> tuple[object, dict | None]:
    """core_version and version_basis as the readings state them.

    A reading that could not be made leaves its build mode as written.
    """
    version = document.get("core_version")
    basis = document.get("version_basis")
    basis = dict(basis) if isinstance(basis, dict) else None
    if isinstance(version, dict):
        version = dict(version)
    for reading in readings:
        if reading.status not in (version_basis.MATCH, version_basis.DRIFT):
            continue
        if reading.mode:
            if not isinstance(version, dict):
                version = {}
            version[reading.mode] = reading.read
        else:
            version = reading.read
        if reading.updates and basis is not None:
            target = basis if not reading.mode else dict(basis.get(reading.mode) or {})
            target.update(dict(reading.updates))
            if reading.mode:
                basis[reading.mode] = target
    return version, basis


def write_version(path: Path, readings: list) -> bool:
    """Set core_version (and a tag basis' tag and distance) from the readings."""
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    version, basis = apply_readings(document, readings)
    if version == document.get("core_version") and basis == document.get("version_basis"):
        return False
    expected = dict(document)
    expected["core_version"] = version
    if basis is not None:
        expected["version_basis"] = basis
    apply_edit(path, set_version_fields(text, version, basis), expected)
    return True


def _needs_review(report: ProfileReport, accept_changed: bool) -> bool:
    """Whether the report leaves a ref to read before the pin may move."""
    # A profile citing nothing has nothing to read again: anarch's pin sat
    # behind a CI-only commit through every bulk advance.
    if report.skip_kind not in (None, SkipKind.NO_SOURCE_REF) or not report.head or report.pinned_tag:
        return True
    blocking = REVIEW_STATUSES if not accept_changed else (
        s for s in REVIEW_STATUSES if s != "CHANGED"
    )
    return any((report.counts or {}).get(s) for s in blocking)


@functools.lru_cache(maxsize=4)
def _platform_cores(emulators_dir: str, platforms_dir: str) -> tuple[tuple[str, frozenset[str]], ...]:
    profiles = load_emulator_profiles(emulators_dir)
    return tuple(
        (platform, frozenset(resolve_platform_cores(
            load_platform_config(platform, platforms_dir), profiles
        )))
        for platform in list_registered_platforms(platforms_dir)
    )


def shipping_platforms(
    name: str, emulators_dir: str, platforms_dir: str = PLATFORMS_DIR,
) -> list[str]:
    """The registered platforms whose cores resolve to this profile."""
    return [
        platform
        for platform, cores in _platform_cores(
            os.path.realpath(emulators_dir), platforms_dir
        )
        if name in cores
    ]


@dataclass(frozen=True)
class Bump:
    """Whether the pin moved, and the reason it was refused when one applies."""

    moved: bool
    refusal: str | None = None


def bump_commit(
    path: Path, report: ProfileReport, accept_changed: bool = False,
    cache_dir: str = DEFAULT_CACHE, offline: bool = False,
    platforms_dir: str = PLATFORMS_DIR,
) -> Bump:
    """Advance source_commit to HEAD when nothing needs a read again.

    core_version moves with the pin, read again from version_basis at the
    new revision. Four bulk advances moved 295 pins and no version: an
    advance whose version cannot be read is refused.
    """
    if not report.head or _needs_review(report, accept_changed):
        return Bump(False)
    text = path.read_text(encoding="utf-8")
    if pending_recale(report, accept_changed, text):
        return Bump(False)
    document = yaml.safe_load(text)
    if document.get("built_by") and not document.get("pin_follows"):
        # The pin is the commit a platform builds (recalbox gsplus.mk, the
        # mame0258 its package fetches), not a point on a moving branch:
        # HEAD is a build nobody ships under this name. A build of the
        # branch tip (RetroPie's advmame) is HEAD, and follows it.
        return Bump(False, (
            f"pinned to the build {', '.join(document['built_by'])} "
            "ships, advanced by hand"
        ))
    if not (document.get("pin_frozen") or document.get("pin_follows")):
        shipped = shipping_platforms(path.stem, str(path.parent), platforms_dir)
        if len(shipped) == 1:
            # One platform ships it, so the pin is the revision that platform
            # builds: a bulk advance moved fheroes2, supertux and
            # supermariowar past what EmuELEC compiles, and rigelengine is
            # already one commit ahead of its package.mk.
            return Bump(False, (
                f"only {shipped[0]} ships it. Read the revision its "
                "build compiles and set pin_frozen, or pin_follows when it "
                "builds the branch tip"
            ))
    if any(isinstance(document.get(f), dict) for f in ("source_commit", "upstream_commit")):
        # A pin per build mode names one revision per repository, and the
        # report heads only the primary one: rewriting str(dict) was a
        # refused write on mesence, supermodel and xemu.
        return Bump(False, "pins keyed by build mode are advanced by hand")
    # An upstream pinned on a release tag is the base the port was cut from:
    # its HEAD is another program, so the bump leaves it on the tag.
    # A profile citing nothing compared nothing upstream: writing that HEAD
    # would claim gme's vendored libgme or hbmame's port is current.
    upstream_moves = bool(
        report.upstream_head
        and report.upstream_pin != report.upstream_head
        and not report.upstream_tag
        and report.skip_kind is not SkipKind.NO_SOURCE_REF
    )
    if document.get("source_commit") == report.head and not upstream_moves:
        # Rewriting the pin to the value it already holds is not a bump, and
        # announcing it buries the profiles that did move.
        return Bump(False)
    if (
        document.get("source_commit") != report.head
        and not cites_primary(report)
    ):
        # Every ref anchored in another repository: HEAD of this one was
        # never compared with anything. gam4980's pin moved to the fork's
        # HEAD while its bare libretro.c refs still described upstream.
        return Bump(False, f"no ref resolves in {report.repo}, its pin is not advanced")
    expected = dict(document)
    expected["source_commit"] = report.head
    new_text = _set_pin(text, document, "source_commit", report.head, "profiled_date")
    if document.get("pin_follows") and report.head:
        new_text, expected = _follow_config_reads(new_text, expected, document, report.head)
    if upstream_moves and report.upstream_head:
        expected["upstream_commit"] = report.upstream_head
        new_text = _set_pin(
            new_text, document, "upstream_commit", report.upstream_head, "source_commit"
        )
    readings = version_basis.check(expected, cache_dir, offline, recompute=True)
    refused = version_refusal(readings)
    if refused:
        return Bump(False, f"{refused}, its pin is not advanced")
    version, basis = apply_readings(expected, readings)
    if version != expected.get("core_version") or basis != expected.get("version_basis"):
        new_text = set_version_fields(new_text, version, basis)
        expected["core_version"] = version
        if basis is not None:
            expected["version_basis"] = basis
    apply_edit(path, new_text, expected)
    return Bump(True)


def version_refusal(readings: list) -> str | None:
    """Why the version at a new pin cannot be stated, or None."""
    for reading in readings:
        if reading.status == version_basis.NO_BASIS:
            return "no version_basis says where its version is read"
        if reading.status == version_basis.UNREADABLE:
            return f"core_version cannot be read at the new pin: {reading.where}"
        if reading.status == version_basis.UNCHECKED:
            return f"core_version is {reading.where}, not read from the code at a pin"
    return None


def pins_changed(before: dict, after: dict) -> list[str]:
    """The pin fields whose value a write changed."""
    return [
        pin for pin in ("source_commit", "upstream_commit")
        if after.get(pin) and after.get(pin) != before.get(pin)
    ]


def cites_primary(report: ProfileReport) -> bool:
    """Whether a ref resolved in the repository source_commit pins.

    A part attributed to another declared repository carries its slug, and one
    read in the primary carries none. A profile citing nothing proves
    nothing either way and is not held back.
    """
    if len(report.repos) < 2:
        return True
    parts = [
        part for entry in report.entries for part in entry.parts
        if part.status != "EXTERNAL"
    ]
    return not parts or any(part.repo is None for part in parts)


def _follow_config_reads(
    text: str, expected: dict, document: dict, head: str
) -> tuple[str, dict]:
    """A config_reads entry read at the pin moves with a pin that follows the
    branch tip: RetroPie installs advmame from the tip, so the build its
    advmame.rc is read at is the pin itself."""
    pin = str(document.get("source_commit") or "")
    reads = document.get("config_reads") or []
    if not pin or not any(isinstance(r, dict) and r.get("revision") == pin for r in reads):
        return text, expected
    text = re.sub(
        r'^(\s*revision:\s*)(["\']?)' + re.escape(pin) + r"\2\s*$",
        lambda m: f"{m.group(1)}{m.group(2)}{head}{m.group(2)}",
        text, flags=re.M,
    )
    expected = {**expected, "config_reads": [
        {**r, "revision": head} if isinstance(r, dict) and r.get("revision") == pin else r
        for r in reads
    ]}
    return text, expected


def _set_pin(text: str, document: dict, field: str, value: str, after: str) -> str:
    """Write *field* as *value*, replacing its line or adding one after *after*."""
    current = document.get(field)
    if current == value:
        return text
    if current:
        return replace_field_line(text, field, str(current), value)[0]
    return insert_after_line(text, after, f'{field}: "{value}"')
