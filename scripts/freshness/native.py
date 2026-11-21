"""The native export's cached originals and published exports against the platform files."""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

from exporter import discover_exporters
from exporter.native import StaleTruth, export_platform, load_inputs
from exporter.originals import SOURCES_INDEX, SourcesIndexUnreadable, load_sources, source_key, wanted_sources
from model.platforms import inheritance_chain
from model.registry import list_registered_platforms
from resolve.reconcile import build_native_model
from freshness.findings import ERROR, OK, STALE, Finding


def native_cache_state(
    wanted: dict[str, str],
    root: Path,
    recorded: dict[str, str],
    index: Path,
    transcribed_at: float,
) -> str:
    """Why a platform's cached originals cannot be patched, '' when they can.

    The export corrects the file our data was transcribed from. A cached
    original is that file only if it came from the URL the platform file
    names today and was fetched no earlier than the platform file was last
    rewritten: a branch URL keeps its name while its content moves.
    """
    for relative, url in sorted(wanted.items()):
        path = root / relative
        if not path.is_file():
            return f"{relative} not cached"
        known = recorded.get(source_key(path, index))
        if known is None:
            return f"{relative} cached from an unrecorded URL"
        if known != url:
            return f"{relative} cached from another revision"
        if path.stat().st_mtime < transcribed_at:
            return f"{relative} cached before the platform file was rewritten"
    return ""


def _export_tree(root: Path, platform: str) -> dict[str, bytes]:
    """A platform's published export: its directory and its report."""
    tree = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in (root / platform).rglob("*") if path.is_file()
    }
    report = root / f"{platform}.json"
    if report.is_file():
        tree[report.name] = report.read_bytes()
    return tree


def published_export_state(
    platform: str,
    exporter_class: type,
    truth_dir: Path,
    platforms_dir: Path,
    cache_dir: Path,
    published: Path,
) -> str:
    """Why the committed export is not what the export writes now, '' when it is.

    exports/ is committed and the site publishes it, but CI cannot rebuild
    it: the originals it patches live in the local cache. A profile change
    that moves a hash leaves the published file behind until someone runs
    the export again, and this is what says so.
    """
    scratch_root = Path("tmp")
    scratch_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch_root) as scratch:
        with contextlib.redirect_stdout(io.StringIO()):
            ok, messages = export_platform(
                platform, exporter_class, truth_dir, Path(scratch),
                str(platforms_dir), cache_dir, False,
            )
        if not ok:
            return f"the export fails: {messages[0] if messages else 'no message'}"
        if _export_tree(Path(scratch), platform) != _export_tree(published, platform):
            return f"{published.as_posix()}/{platform} is not what the export writes now"
    return ""


def _transcribed_at(platforms_dir: Path, platform: str) -> float:
    """Last rewrite of the platform file or of any file it inherits."""
    return max(
        ((platforms_dir / f"{name}.yml").stat().st_mtime
         for name in inheritance_chain(platform, platforms_dir)),
        default=0.0,
    )


# How the truth model settles two cores' hashes: generate_truth reports it,
# and it says nothing about whether a cached original is current.
_MODEL_NOTES = ("WARNING: hash conflict",)


@contextlib.contextmanager
def _without_model_notes() -> Iterator[None]:
    """Keep the model build's own notes out of the freshness report.

    Anything else written to stderr passes through.
    """
    sink = io.StringIO()
    try:
        with contextlib.redirect_stderr(sink):
            yield
    finally:
        for line in sink.getvalue().splitlines(keepends=True):
            if not line.startswith(_MODEL_NOTES):
                sys.stderr.write(line)


def check_native(
    platforms_dir: Path, cache_dir: Path, truth_dir: Path,
    published: Path = Path("exports"),
) -> list[Finding]:
    exporters = discover_exporters()
    index = cache_dir / SOURCES_INDEX
    try:
        recorded = load_sources(cache_dir)
    except SourcesIndexUnreadable as exc:
        return [Finding("native", index.name, ERROR, detail=str(exc))]
    findings: list[Finding] = []
    for name in list_registered_platforms(str(platforms_dir)):
        exporter_class = exporters.get(name)
        if not exporter_class:
            continue
        with _without_model_notes():
            try:
                truth, scraped = load_inputs(name, truth_dir, str(platforms_dir))
            except StaleTruth as exc:
                findings.append(Finding("native", name, STALE, detail=str(exc)))
                continue
            systems, _ = build_native_model(truth or {}, scraped)
            wanted = wanted_sources(exporter_class(), systems, scraped)
            reason = native_cache_state(
                wanted, cache_dir / name, recorded, index, _transcribed_at(platforms_dir, name)
            )
            if reason:
                reason += (
                    f", python scripts/export_native.py --platform {name} --refresh-cache"
                    " fetches it, then the export is written again"
                )
            else:
                reason = published_export_state(
                    name, exporter_class, truth_dir, platforms_dir, cache_dir, published
                )
                if reason:
                    reason += f", python scripts/export_native.py --platform {name} writes it again"
        findings.append(
            Finding(
                "native",
                name,
                STALE if reason else OK,
                local=f"{len(wanted)} file(s)",
                detail=reason,
            )
        )
    return sorted(findings, key=lambda f: f.subject)
