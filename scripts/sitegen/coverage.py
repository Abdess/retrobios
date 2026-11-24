"""Coverage of each platform as verify counts it, cached between the site and README builds."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

from core.cli import InputMissing
from core.offline import run_is_offline
from core.paths import DB_FILE, EMULATORS_DIR, REPO_ROOT
from model import siteinputs
from model.largefiles import LARGE_FILES_CACHE
from model.platforms import load_platform_config
from model.registry import load_data_dir_registry, versions_file_for
from packs.coverage import verify_platform
from packs.shares import core_shares
from packs.verdicts import blocking_missing
from sitegen.install import display_name


# The repository's profiles wherever the script is run from: a bare
# "emulators" read the working directory, and a run elsewhere counted 0 cores.
_EMULATORS_DIR = str(REPO_ROOT / EMULATORS_DIR)


def compute_coverage(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    data_registry: dict | None = None,
    emulators_dir: str = _EMULATORS_DIR,
) -> dict:
    config = load_platform_config(platform_name, platforms_dir)
    result = verify_platform(
        config,
        db,
        emulators_dir,
        data_dir_registry=data_registry,
    )
    sc = result.get("status_counts", {})
    ok = sc.get("ok", 0)
    untested = sc.get("untested", 0)
    missing = sc.get("missing", 0)
    total = result["total_files"]
    # An UNTESTED file the builder refuses (its declared hash contradicted on
    # a hash platform) is held, not packed.
    present = ok + untested - len(result.get("excluded_files", []))
    pct = (present / total * 100) if total > 0 else 0
    # verify's own count of what the cores add: one file per pack path, held
    # but unplaced and installed-with-the-emulator files apart. Recounting
    # the gap entries here said 7956 packed and 419 missing for RetroArch,
    # where verify says 7977 and 66.
    shares = core_shares(result)
    return {
        "platform": display_name(config, platform_name),
        "total": total,
        "verified": ok,
        "untested": untested,
        "missing": missing,
        "missing_not_firmware": {
            category: len(dests)
            for category, dests in (result.get("missing_not_firmware") or {}).items()
        },
        "present": present,
        "percentage": pct,
        "core_present": shares.packed,
        "core_missing": shares.missing,
        "core_unplaced": shares.held_unplaced,
        # Files a profile marks unsourceable never reach the undeclared list:
        # verify counts them apart, one per slot, under the same rules.
        "core_unsourceable": len(result.get("unsourceable_files", [])),
        "mode": config.get("verification_mode", "existence"),
        # The gaps page badge: verify's count, never refiltered from details.
        "required_missing": blocking_missing(
            result["severity_counts"], result["verification_mode"]),
        "details": result["details"],
        "config": config,
        "ground_truth": result.get(
            "ground_truth_coverage",
            {"with_validation": 0, "platform_only": total, "total": total},
        ),
    }


# The site and the README read the same coverage: the first generator to run
# stores it here and the second reads it back, instead of verifying every
# platform twice (about a minute of the site build).
COVERAGE_CACHE_DIR = REPO_ROOT / "tmp" / "coverage-cache"
_COVERAGE_CACHE_FORMAT = "5"


def _coverage_inputs(db_path: Path, platforms_dir: str, emulators_dir: str) -> str:
    """A digest of everything coverage is computed from.

    The database, the platform and emulator files, the code, the install
    manifests, the data directory revisions, the state of bios/ on disk, and
    what a release asset resolves to: the large-file cache and whether this
    run may download. A test run is offline with its own cache, and its
    result was read back by the next normal run (Lakka 534/535 for 535/535).
    A change to any of them computes the coverage again.
    """
    import hashlib

    digest = hashlib.sha256(_COVERAGE_CACHE_FORMAT.encode())

    def add_file(path: Path) -> None:
        digest.update(str(path).encode() + b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"<absent>")

    add_file(db_path.resolve())
    # The repository's manifests and bios/, and those beside a given database.
    beside = db_path.resolve().parent
    manifests = dict.fromkeys((REPO_ROOT / "install", siteinputs.manifests_dir().resolve()))
    for root, pattern in ((Path(platforms_dir), "*"), (Path(emulators_dir), "*.yml"),
                          (REPO_ROOT / "scripts", "*.py"),
                          *((folder, "*.json") for folder in manifests),
                          (REPO_ROOT / "recipes", "*.json")):
        for path in sorted(p for p in root.resolve().rglob(pattern) if p.is_file()):
            add_file(path)
    revisions = sorted({REPO_ROOT / versions_file_for(entry)
                        for entry in load_data_dir_registry(platforms_dir).values()
                        if entry.get("local_cache")})
    for path in (REPO_ROOT / ".gitignore", REPO_ROOT / "mame_clones.json", *revisions):
        add_file(path)
    digest.update(b"offline\0" + (b"1" if run_is_offline() else b"0") + b"\n")
    large = Path(LARGE_FILES_CACHE).resolve()
    digest.update(str(large).encode() + b"\0")
    for path in sorted(large.glob("*")) if large.is_dir() else ():
        if path.is_file():
            stat = path.stat()
            digest.update(f"{path.name}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
    for bios in dict.fromkeys((REPO_ROOT / "bios", beside / "bios")):
        for path in sorted(bios.rglob("*")):
            if path.is_file():
                stat = path.stat()
                digest.update(f"{path.relative_to(bios)}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def platform_coverages(
    platform_names: list[str],
    platforms_dir: str,
    db: dict,
    data_registry: dict | None = None,
    emulators_dir: str = _EMULATORS_DIR,
    db_path: str = DB_FILE,
    report: Callable[[str, dict], None] | None = None,
) -> dict[str, dict]:
    """compute_coverage for each platform, read from the cache when its
    inputs have not changed since a generator last stored it.

    A platform with no YAML is left out, as compute_coverage raises for it.
    ``report`` is called with each platform and its coverage.
    """
    # pickle, not JSON: the coverage holds sets and enums that JSON would
    # turn into lists and strings. The file is written by this function into
    # the repository's own tmp/, never downloaded.
    import pickle

    key = _coverage_inputs(Path(db_path), platforms_dir, emulators_dir)
    names = sorted(platform_names)
    cache = COVERAGE_CACHE_DIR / f"{key}.pickle"
    coverages: dict[str, dict] | None = None
    if cache.is_file():
        try:
            with cache.open("rb") as handle:
                stored = pickle.load(handle)
        except (OSError, EOFError, pickle.UnpicklingError) as exc:
            print(f"  coverage cache unreadable, computing again: {exc}", file=sys.stderr)
        else:
            if stored.get("platforms") == names:
                coverages = stored["coverages"]
                print(f"  coverage read from {cache.relative_to(REPO_ROOT)}")
    if coverages is None:
        coverages = {}
        for name in names:
            try:
                coverages[name] = compute_coverage(
                    name, platforms_dir, db, data_registry, emulators_dir=emulators_dir,
                )
            except InputMissing:
                # A missing profile or platform directory is no platform
                # left out: it emptied every one and cached the result.
                raise
            except FileNotFoundError as exc:
                print(f"  {name}: skipped ({exc})", file=sys.stderr)
        COVERAGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        scratch = cache.with_suffix(f".{os.getpid()}.tmp")
        with scratch.open("wb") as handle:
            pickle.dump({"platforms": names, "coverages": coverages}, handle,
                        protocol=pickle.HIGHEST_PROTOCOL)
        scratch.replace(cache)
        # generate_site and generate_readme both purge here. One unlinking
        # what the other had just listed ended it on FileNotFoundError.
        for stale in COVERAGE_CACHE_DIR.glob("*.pickle"):
            if stale != cache:
                stale.unlink(missing_ok=True)
    ordered = {name: coverages[name] for name in platform_names if name in coverages}
    if report:
        for name in names:
            if name in ordered:
                report(name, ordered[name])
    return ordered
