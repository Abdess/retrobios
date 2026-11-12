#!/usr/bin/env python3
"""Run the full retrobios pipeline.

Steps, numbered as the run prints them:
  0    validate_schemas.py          profiles and platform YAMLs, as PR CI checks them
  1    generate_db.py --force       rebuild database.json from bios/
  1b   provenance_report.py         dump-catalog coverage, derivable.json
  1c   romset_recipes.py            archive identification, reconstruction targets,
                                    and --capture: recipes/archives.json
  2    refresh_data_dirs.py         Dolphin Sys, PPSSPP assets and the other trees
  2a   mame_hash_scraper            MAME BIOS hashes, and device sets on a new release
  2a2  fbneo_hash_scraper           FBNeo BIOS hashes
  2b   check_buildbot_system.py     buildbot freshness (--check-buildbot)
  2b2  check_release_assets.py      large-files release vs gitignored files
  2c   generate_truth.py            truth models (--with-truth, --with-export)
  2d   diff_truth.py                truth vs scraped platforms
  2e   export_native.py             corrected native files (--with-export)
  3    verify.py --all              every platform, native logic
  3a   identity.py --strict         one content under two identities
  3b   slots.py                     destinations both layers claim
  4    generate_pack.py --all       ZIP packs
  4b   generate_pack.py --manifest  install manifests
  4c   --manifest-targets           per-target core lists
  4d   bundled_only.py --strict     copies only an emulator install provides
  4e   generate_games_index.py      install/games/: what the games-on-card mode reads
  5    consistency check            verify == pack: counts, paths, emulator and system packs,
                                    narrowed platform packs (see check_narrowed_packs)
  6    --verify-packs               pack integrity, extraction and hashes
  7    generate_readme.py           README.md and CONTRIBUTING.md
       generate_installer_doc.py    run samples and tables of wiki/installer.md
       generate_report_excerpt.py   the verify excerpt of wiki/reading-reports.md
  8    generate_site.py             site pages, into the Starlight project in website/
  8b   npm run build (website/)     rendered as the site deploy renders it, then validate_site.py

--offline skips 2 to 2b2 and the network side of 2e and 4: release assets
come from .cache/large/ only.

Usage:
    python scripts/pipeline.py                    # every registered platform
    python scripts/pipeline.py --skip-packs       # skip steps 4, 4b, 4c, 5 and 6
    python scripts/pipeline.py --skip-docs        # skip steps 7, 8 and 8b
    python scripts/pipeline.py --offline          # no network, see above
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

# The build scripts need CPython 3.9, which builds the same database,
# manifests and packs as 3.12.
# On an older interpreter the run got through the first steps and failed in
# the packs, so it stops before step 0. A test compiles every script under
# this floor.
if sys.version_info < (3, 9):
    sys.exit(f"pipeline.py needs Python 3.9 or newer, this is {sys.version.split()[0]}")

sys.path.insert(0, str(Path(__file__).parent))
from common import (
    ArtifactLockBusy,
    artifact_lock,
    github_token,
    hold_artifact_lock,
    hold_repository_outputs,
    load_data_dir_registry,
    publish_hold,
)
from refresh_data_dirs import hold_data_dirs
from packpaths import MEDIA_MARKER


class StepResults(dict):
    """The outcome of each step, and how long it took.

    A step's time runs from the previous step's outcome to its own, so the
    in-process steps (consistency, the truth diff) are timed like the ones
    run() launches. The summary prints it: finding the slow step in a
    twenty-minute run meant reading the whole log.
    """

    def __init__(self, start: float) -> None:
        super().__init__()
        self.seconds: dict[str, float] = {}
        self._mark = start

    def __setitem__(self, step: str, outcome: object) -> None:
        now = time.monotonic()
        self.seconds[step] = self.seconds.get(step, 0.0) + now - self._mark
        self._mark = now
        super().__setitem__(step, outcome)



# Steps that report without failing the run.
NON_BLOCKING = frozenset({"check_buildbot"})

# Every step in run order, by its results key. The position and the total
# printed during the run come from this list: hand-written "N/8" labels
# counted 8 steps in a run of 24, and the eighth came before 8b. The summary
# prints the same labels the run printed, so a FAILED row is found in the
# log by its number.
STEP_LABELS: dict[str, str] = {
    "validate_schemas": "0 validate schemas",
    "generate_db": "1 generate database",
    "provenance": "1b provenance report",
    "romset_recipes": "1c romset recipes",
    "refresh_data": "2 refresh data directories",
    "mame_hashes": "2a refresh MAME hashes",
    "fbneo_hashes": "2a2 refresh FBNeo hashes",
    "check_buildbot": "2b check buildbot system",
    "check_release_assets": "2b2 check release assets",
    "generate_truth": "2c generate truth",
    "diff_truth": "2d diff truth",
    "export_native": "2e export native",
    "verify": "3 verify all platforms",
    "identity": "3a file identity",
    "slots": "3b slot arbitration",
    "generate_packs": "4 generate packs",
    "generate_manifests": "4b generate install manifests",
    "generate_target_manifests": "4c generate target manifests",
    "bundled_only": "4d copies only an emulator install provides",
    "games_index": "4e games index",
    "consistency": "5 consistency check",
    "pack_integrity": "6 pack integrity",
    "generate_readme": "7 generate readme",
    "generate_site": "8 generate site",
    "render_site": "8b render site",
}
_KEY_BY_LABEL = {label: key for key, label in STEP_LABELS.items()}


def step_number(key: str) -> str:
    """The number a step's progress lines carry ("2b2", "4d")."""
    return STEP_LABELS[key].split(" ", 1)[0]


def step_title(label: str) -> str:
    """What the run prints for a label: its name and its place in the run.

    A second command of one step ("2c generate truth (export model)") is
    printed as written.
    """
    key = _KEY_BY_LABEL.get(label)
    if key is None:
        return label
    return f"{label} [{list(STEP_LABELS).index(key) + 1}/{len(STEP_LABELS)}]"


def skip_notice(key: str, reason: str = "") -> None:
    """The line a step that does not run prints in place of its output."""
    because = f" ({reason})" if reason else ""
    print(f"\n--- {step_title(STEP_LABELS[key])}: SKIPPED{because} ---")

def _output_dir(typed: str | None) -> str:
    """The pack directory as an absolute path.

    Every step runs from the repository root, while the lock and the purge
    of stale packs ran here, against the caller's directory: started from
    scripts/, the run locked and purged scripts/dist/ and wrote its packs to
    dist/. A directory the caller typed is read from where they typed it.
    """
    if typed is None:
        return str(Path(__file__).resolve().parent.parent / "dist")
    return str(Path(typed).resolve())


def run(cmd: list[str], label: str) -> tuple[bool, str]:
    """Run a command, echoing its output as it comes. Returns (success, output).

    The output used to be captured and printed when the step ended, stderr
    after stdout: a twenty-minute pack build showed nothing, and a warning
    landed far from the line it was about. One stream, read line by line.
    """
    title = step_title(label)
    print(f"\n--- {title} ---", flush=True)
    start = time.monotonic()
    repo_root = str(Path(__file__).resolve().parent.parent)
    lines: list[str] = []
    with subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        # Node's compile cache lands in /tmp, a 4 GB tmpfs here: the site
        # build filled it to 3.4 GB across a day of pipeline runs.
        cwd=repo_root,
        env={**os.environ, "PYTHONUNBUFFERED": "1", "NODE_DISABLE_COMPILE_CACHE": "1"},
    ) as proc:
        for line in proc.stdout:
            lines.append(line)
            print(line, end="", flush=True)
        returncode = proc.wait()
    elapsed = time.monotonic() - start

    ok = returncode == 0
    print(f"--- {title}: {'OK' if ok else 'FAILED'} ({elapsed:.1f}s) ---")
    return ok, "".join(lines)


def parse_verify_counts(output: str) -> dict[str, tuple[int, int]]:
    """Extract per-group OK/total from verify output.

    Matches: "Label: X/Y OK ..." or "Label: X/Y present ..."
    Returns {group_label: (ok, total)}.
    """
    counts = {}
    for line in output.splitlines():
        m = re.match(r"^(.+?):\s+(\d+)/(\d+)\s+(OK|present)", line)
        if m:
            label = m.group(1).strip()
            ok, total = int(m.group(2)), int(m.group(3))
            for name in label.split(" / "):
                counts[name.strip()] = (ok, total)
    return counts


def parse_verify_extras(output: str) -> dict[str, int]:
    """Core files and game data verify says each pack carries, per platform.

    Read from the "Core files: N in pack" and "Game data: N in pack" lines
    that follow a platform's summary line.
    """
    extras: dict[str, int] = {}
    names: list[str] = []
    for line in output.splitlines():
        m = re.match(r"^(.+?):\s+(\d+)/(\d+)\s+(OK|present)", line)
        if m:
            names = [name.strip() for name in m.group(1).split(" / ")]
            for name in names:
                extras[name] = 0
            continue
        packed = re.match(r"^\s+(?:Core files|Game data): (\d+) in pack", line)
        if packed and names:
            for name in names:
                extras[name] += int(packed.group(1))
    return extras


def parse_pack_extras(output: str) -> dict[str, int]:
    """Files each full pack takes from the cores, per pack label."""
    extras: dict[str, int] = {}
    current_label = ""
    for line in output.splitlines():
        m = re.match(r"Generating (?:shared )?pack for (.+)\.\.\.", line)
        if m:
            current_label = _full_pack_label(m.group(1).strip())
            continue
        cores = re.search(r"\+ (\d+) from cores\)", line)
        if current_label and "files packed" in line and cores:
            extras[current_label] = int(cores.group(1))
    return extras


def _full_pack_label(label: str) -> str:
    """The pack name, or "" for a reduced variant such as [source=platform]."""
    meta = re.search(r"\s+\[([^\]]+)\]$", label)
    if meta is None:
        return label
    return label[: meta.start()] if meta.group(1) == "source=full" else ""


def parse_pack_counts(output: str) -> dict[str, tuple[int, int]]:
    """Extract per-pack OK/total from generate_pack output.

    Returns {pack_label: (ok, total)}.
    """
    counts = {}
    current_label = ""
    for line in output.splitlines():
        m = re.match(r"Generating (?:shared )?pack for (.+)\.\.\.", line)
        if m:
            # Labels carry execution metadata such as ``[source=full]``. Only
            # the full, unreduced pack is what verify describes: with
            # --all-variants the six variants shared one label and the last
            # (platform, required) was compared to the full report.
            current_label = _full_pack_label(m.group(1).strip())
            continue
        if not current_label:
            continue
        if "files packed" not in line:
            continue
        # "622 files packed (359 baseline + 263 from cores), 358/359 files OK"
        ok_m = re.search(r"(\d+)/(\d+) files OK", line)
        if ok_m:
            counts[current_label] = (int(ok_m.group(1)), int(ok_m.group(2)))
    return counts


def parse_pack_exclusions(output: str) -> dict[str, int]:
    """Extract intentional unsafe-omission counts from pack output."""
    exclusions: dict[str, int] = {}
    current_label = ""
    for line in output.splitlines():
        label_match = re.match(r"Generating (?:shared )?pack for (.+)\.\.\.", line)
        if label_match:
            # The same reading as parse_pack_counts: a reduced variant must
            # not overwrite the full pack's count under the shared label.
            current_label = _full_pack_label(label_match.group(1).strip())
            continue
        if not current_label or "files packed" not in line:
            continue
        excluded_match = re.search(r"(\d+) unsafe excluded", line)
        exclusions[current_label] = (
            int(excluded_match.group(1)) if excluded_match else 0
        )
    return exclusions


def _match_key(label: str) -> set[str]:
    """Comparable identity for a platform label.

    Display labels and registry ids differ in punctuation and spacing
    (``MiSTer FPGA`` against ``misterfpga``), and grouped packs join their
    members with either separator.
    """
    return {
        re.sub(r"[^a-z0-9]+", "", part.strip().lower())
        for part in label.replace("+", "/").split("/")
    } - {""}


def release_pack_keys(platforms_dir: str = "platforms") -> set[str]:
    """Comparable identities of the platforms --all builds a pack for: their
    registry ids and display names, normalized as _match_key does."""
    from common import list_release_pack_platforms, load_platform_config  # noqa: PLC0415

    keys: set[str] = set()
    for name in list_release_pack_platforms(platforms_dir):
        keys |= _match_key(name)
        keys |= _match_key(str(load_platform_config(name, platforms_dir).get("platform", name)))
    return keys


def check_consistency(
    verify_output: str, pack_output: str, released: set[str] | None = None,
) -> bool:
    """Verify that check counts match between verify and pack for each platform.

    *released* holds the identities of the platforms with a release pack
    (release_pack_keys). verify judges every platform, the build only those:
    a platform outside it has no pack to compare, which is no failure.
    """
    v = parse_verify_counts(verify_output)
    p = parse_pack_counts(pack_output)
    excluded = parse_pack_exclusions(pack_output)
    verify_extras = parse_verify_extras(verify_output)
    pack_extras = parse_pack_extras(pack_output)

    print(f"\n--- {step_title(STEP_LABELS['consistency'])} ---")
    all_ok = True
    if not v or not p:
        # Nothing parsed is nothing compared: a changed output format would
        # otherwise pass the check without a single platform in it.
        print(f"  parsed {len(v)} verify and {len(p)} pack results: nothing to compare")
        all_ok = False
    for p_label in sorted(p):
        if not any(_match_key(p_label) & _match_key(v_label) for v_label in v):
            print(f"  {p_label}: pack with no verify result")
            all_ok = False

    for v_label, (v_ok, v_total) in sorted(v.items()):
        # Match by normalized name overlap.  Platform display labels and
        # registry IDs legitimately differ in punctuation and spacing
        # (notably ``MiSTer FPGA`` vs ``misterfpga``).
        p_match = None
        v_names = _match_key(v_label)
        for p_label in p:
            if v_names & _match_key(p_label):
                p_match = p_label
                break

        if p_match and p_match in pack_extras and v_label in verify_extras:
            if verify_extras[v_label] != pack_extras[p_match]:
                # The cores' share: the base check passed RomM while verify
                # counted 412 core files and game data and the pack held 60.
                print(
                    f"  {v_label}: MISMATCH core files verify "
                    f"{verify_extras[v_label]} != pack {pack_extras[p_match]}"
                )
                all_ok = False
        if p_match:
            p_ok, p_total = p[p_match]
            p_excluded = excluded.get(p_match, 0)
            if v_total != p_total:
                print(f"  {v_label}: MISMATCH total verify {v_total} != pack {p_total}")
                all_ok = False
            elif p_ok == v_ok:
                print(
                    f"  {v_label}: verify {v_ok}/{v_total} == pack {p_ok}/{p_total} OK"
                )
            else:
                # Both ways are a disagreement. A pack exclusion never covers
                # a file verify counts OK: an existence platform ships a file
                # whose hash disagrees, and a hash platform's verify reports
                # it untested, so the counts can only differ by a defect.
                print(
                    f"  {v_label}: MISMATCH pack {p_ok}/{p_total} OK "
                    f"({p_excluded} unsafe excluded) != verify {v_ok}/{v_total}"
                )
                all_ok = False
        elif released is not None and not (v_names & released):
            print(f"  {v_label}: {v_ok}/{v_total} (no release pack, served by the installer)")
        else:
            print(f"  {v_label}: MISSING pack: verify judged {v_ok}/{v_total} "
                  "but the build wrote no pack for it")
            all_ok = False

    status = "OK" if all_ok else "FAILED"
    print(f"--- {step_title(STEP_LABELS['consistency'])}, counts: {status} ---")
    return all_ok


def parse_pack_paths(output: str) -> dict[str, str]:
    """The archive each full pack was written to, per pack label."""
    paths: dict[str, str] = {}
    current_label = ""
    for line in output.splitlines():
        m = re.match(r"Generating (?:shared )?pack for (.+)\.\.\.", line)
        if m:
            current_label = _full_pack_label(m.group(1).strip())
            continue
        written = re.match(r"^\s+(\S.*?\.zip): \d+ files packed", line)
        if current_label and written:
            paths[current_label] = written.group(1)
    return paths


# Members the builder writes for the reader or the device rather than for a
# core: the documents, and the empty marker an Android pack carries.
_PACK_NOTES = re.compile(
    r"(^README\.txt$|^manifest\.json$|(^|/)(INSTRUCTIONS|RENAMED)_[^/]*\.txt$"
    rf"|(^|/){re.escape(MEDIA_MARKER)}$)"
)


def _tree_members(
    platform: str, platforms_dir: str, emulators_dir: str = "emulators",
) -> dict[str, int]:
    """Archive path -> size of every file the platform's data trees can add."""
    import generate_pack  # noqa: PLC0415
    from common import load_emulator_profiles, load_platform_config  # noqa: PLC0415
    from packpaths import _flat  # noqa: PLC0415

    config = load_platform_config(platform, platforms_dir)
    base_dest = config.get("base_destination", "")
    registry = load_data_dir_registry(platforms_dir)
    core_trees = generate_pack.core_data_trees(
        config, load_emulator_profiles(emulators_dir), platform, registry,
    )
    members: dict[str, int] = {}
    with contextlib.redirect_stdout(io.StringIO()):
        for src, full in generate_pack._data_directory_members(
            config.get("systems", {}), registry,
            platform, base_dest, False, set(), set(), set(),
            core_trees=core_trees,
        ):
            members[_flat(full, base_dest, True)] = os.path.getsize(src)
    return members


def _set_difference_lines(label: str, credited: set[str], written: set[str]) -> list[str]:
    """The paths one side has and the other lacks, ten of each at most."""
    lines = []
    for side, paths in (("verify only", credited - written), ("pack only", written - credited)):
        if paths:
            shown = ", ".join(sorted(paths)[:10])
            more = f" (+{len(paths) - 10})" if len(paths) > 10 else ""
            lines.append(f"  {label}: {side} {len(paths)}: {shown}{more}")
    return lines


def check_pack_destinations(
    destinations_file: str, pack_output: str, platforms_dir: str = "platforms",
) -> bool:
    """Compare the paths verify credits with the members of each archive.

    Equal counts hid a file credited on one side and another written on the
    other. The trees and the notes are the archive's own: a tree member is
    set aside when its path and size are the cached file's and verify does
    not credit the path.
    """
    import json  # noqa: PLC0415
    import zipfile  # noqa: PLC0415

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, destinations ---")
    try:
        credited_by = json.loads(Path(destinations_file).read_text())
    except (OSError, ValueError) as exc:
        print(f"  no destinations from verify ({exc})")
        return False
    paths = parse_pack_paths(pack_output)
    if not paths:
        print("  no archive named in the pack output")
        return False
    all_ok = True
    for label, zip_path in sorted(paths.items()):
        names = [n for n in credited_by if _match_key(n) & _match_key(label)]
        if not names:
            print(f"  {label}: no verify destinations")
            all_ok = False
            continue
        entry = credited_by[names[0]]
        credited = set(entry["pack_destinations"])
        trees = _tree_members(entry["platform"], platforms_dir)
        with zipfile.ZipFile(zip_path) as zf:
            written = {
                info.filename for info in zf.infolist()
                if not info.is_dir()
                and not _PACK_NOTES.search(info.filename)
                and not (
                    trees.get(info.filename) == info.file_size
                    and info.filename not in credited
                )
            }
        lines = _set_difference_lines(label, credited, written)
        if lines:
            print("\n".join(lines))
            all_ok = False
        else:
            print(f"  {label}: {len(credited)} paths, the same on both sides")
    return all_ok


# The narrowings an emulator or system pack takes, compared by
# check_emulator_packs. A test holds this to the builder's parameters.
EMULATOR_NARROWINGS_COMPARED = frozenset({"standalone", "regions", "required_only"})


def emulator_variants(profiles: list[dict], full: bool) -> list[tuple[str, dict]]:
    """(label, builder arguments) of each narrowed emulator pack compared.

    --required-only always, and each region the profiles' files declare,
    sampled as check_narrowed_packs samples them unless *full*. A profile
    without a regional file has nothing --region could withdraw.
    """
    import region as region_mod  # noqa: PLC0415

    regions = sorted({
        r for profile in profiles for fe in profile.get("files") or []
        for r in region_mod.normalize_declared(fe.get("region"))
    })
    variants: list[tuple[str, dict]] = [("", {}), (" --required-only", {"required_only": True})]
    variants += [
        (f" --region {regions[i]}", {"regions": [regions[i]]})
        for i in _matrix_coverage(full, len(regions))
    ]
    return variants


def check_emulator_packs(
    emulators_dir: str = "emulators", platforms_dir: str = "platforms",
    db_path: str = "database.json", full: bool = False,
) -> bool:
    """Build every emulator and system pack in memory and compare it with verify.

    Each profile in each build it has (libretro, standalone), full and under
    each narrowing of emulator_variants: the paths the pack fills with the
    profile's files against the ones verify credits. The region and
    required-only rules are written twice, once per side, and only this
    comparison holds them together. No archive is written and no file read.
    """
    import generate_pack  # noqa: PLC0415
    import packresolve  # noqa: PLC0415
    import verify  # noqa: PLC0415
    from common import (  # noqa: PLC0415
        ProfileSelectionError,
        _norm_system_id,
        build_zip_contents_index,
        load_database,
        load_emulator_profiles,
        profiles_for_systems,
        select_emulator_profiles,
    )

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, emulator packs ---")
    db = load_database(db_path)
    zip_contents = build_zip_contents_index(db)
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)

    def compare(names: list[str], standalone: bool, label: str, **narrowing: object) -> bool:
        record = generate_pack.PackRecord()
        was_offline = packresolve._OFFLINE
        # The pack is built offline: verify counts a release asset the cache
        # lacks the same way, missing, as the narrowed-pack step does.
        packresolve.set_offline(True)
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                generate_pack.generate_emulator_pack(
                    names, emulators_dir, db, "bios", "", standalone, zip_contents,
                    offline=True, platforms_dir=platforms_dir, record=record, **narrowing,
                )
                report = verify.verify_emulator(
                    names, emulators_dir, db, standalone, platforms_dir=platforms_dir,
                    **narrowing,
                )
        finally:
            packresolve.set_offline(was_offline)
        lines = _set_difference_lines(
            label, set(report["pack_destinations"]), set(record.files)
        )
        if lines:
            print("\n".join(lines))
        return not lines

    all_ok = True
    compared = 0
    for name in sorted(profiles):
        if profiles[name].get("type") == "alias":
            continue  # selects the profile it names, compared under that name
        for standalone in (False, True):
            try:
                select_emulator_profiles([name], profiles, standalone)
            except ProfileSelectionError:
                continue
            for tag, narrowing in emulator_variants([profiles[name]], full):
                compared += 1
                label = f"{name}{' --standalone' if standalone else ''}{tag}"
                all_ok = compare([name], standalone, label, **narrowing) and all_ok
    print(f"  {compared} emulator packs compared, {'all equal' if all_ok else 'differences above'}")
    # A system pack builds every profile of the system together: a placement
    # rule that only goes wrong when two profiles share a path (the bluemsx
    # tree beside msx-emu's files) never meets in a one-profile pack.
    systems = sorted({
        _norm_system_id(str(sid))
        for profile in profiles.values()
        if profile.get("type") not in ("launcher", "alias") and profile.get("role") != "test"
        for sid in profile.get("systems") or []
    })
    systems_ok = True
    compared = 0
    for sid in systems:
        for standalone in (False, True):
            matching = profiles_for_systems(profiles, [sid], standalone)
            if len(matching) < 2:
                continue
            for tag, narrowing in emulator_variants(
                [profiles[n] for n in matching if n in profiles], full
            ):
                compared += 1
                label = f"--system {sid}{' --standalone' if standalone else ''}{tag}"
                systems_ok = compare(
                    matching, standalone, label, system_ids=[sid], **narrowing
                ) and systems_ok
    print(f"  {compared} system packs compared, "
          f"{'all equal' if systems_ok else 'differences above'}")
    return all_ok and systems_ok


# How each _narrowings() dimension of a platform pack is compared by
# check_narrowed_packs, or why it is not. A test reads the builder's
# signature against these two tables, so a new narrowing fails it until it
# is compared or a reason is written here. Emulator packs have their own
# table, EMULATOR_NARROWINGS_COMPARED.
NARROWINGS_COMPARED = frozenset({"regions", "target_name", "required_only", "no_game_data"})
NARROWINGS_NOT_COMPARED = {
    "standalone": "an emulator pack mode, compared by check_emulator_packs",
    "source": "verify has no platform-only or truth-only report to compare with",
    "one_per_slot": "verify has no slot choice to compare with",
}


def _matrix_coverage(full: bool, count: int) -> range | list[int]:
    """Which of *count* variants of one dimension a run compares.

    The full matrix takes every one. The default takes the first, the last
    and one in between, which reaches each code path the dimension takes
    (an empty selection, a single system, a large one) without its cost.
    """
    if full or count <= 3:
        return range(count)
    return sorted({0, count // 2, count - 1})


def narrowed_variants(
    platform: str, config: dict, profiles: dict, platforms_dir: str, full: bool,
) -> list[tuple[str, dict]]:
    """(label, builder arguments) of each narrowed pack compared for a platform.

    Every region a file of the platform's cores declares, every hardware
    target, every system, --no-game-data and --required-only. Without
    *full*, regions, targets and systems are sampled (_matrix_coverage).
    """
    import region as region_mod  # noqa: PLC0415
    from common import list_available_targets  # noqa: PLC0415

    regions = sorted({
        r for entry in region_mod.platform_region_index(config, profiles).values()
        for r in entry["regions"]
    })
    targets = [t["name"] for t in list_available_targets(platform, platforms_dir)]
    systems = sorted(config.get("systems") or {})
    variants: list[tuple[str, dict]] = [
        ("--required-only", {"required_only": True}),
        ("--no-game-data", {"no_game_data": True}),
    ]
    variants += [
        (f"--region {regions[i]}", {"regions": [regions[i]]})
        for i in _matrix_coverage(full, len(regions))
    ]
    variants += [
        (f"--target {targets[i]}", {"target_name": targets[i]})
        for i in _matrix_coverage(full, len(targets))
    ]
    variants += [
        (f"--system {systems[i]}", {"system_filter": [systems[i]]})
        for i in _matrix_coverage(full, len(systems))
    ]
    return variants


def check_narrowed_packs(
    emulators_dir: str = "emulators", platforms_dir: str = "platforms",
    db_path: str = "database.json", full: bool = False,
) -> bool:
    """Build each narrowed platform pack in memory and compare it with verify.

    The paths the pack writes against the ones verify credits for the same
    narrowing, as check_pack_destinations compares the full packs. Both sides
    run offline: a release asset the cache lacks is missing on each.

    Coverage: --required-only and --no-game-data for every platform, and
    --region, --target and --system. Measured on 2026-11-05, the full matrix
    is 1,150 packs and took 25 minutes, one to two seconds a pack, most
    of it platform-wide work (slot overrides, the gap report) that each build
    redoes. A run therefore takes the first, middle and last region, target
    and system of each platform, 155 packs in about 3 minutes: each value of
    a dimension runs the same code, so three reach every path a narrowing
    takes (the empty end, one system, a large one). *full* (--full-narrowings)
    compares every value. NARROWINGS_NOT_COMPARED says why --source and
    --one-per-slot are not compared.
    """
    import generate_pack  # noqa: PLC0415
    import packresolve  # noqa: PLC0415
    import verify  # noqa: PLC0415
    from common import (  # noqa: PLC0415
        build_zip_contents_index,
        group_identical_platforms,
        list_registered_platforms,
        load_database,
        load_emulator_profiles,
        load_platform_config,
        load_target_config,
    )

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, narrowed packs ---")
    db = load_database(db_path)
    zip_contents = build_zip_contents_index(db)
    profiles = load_emulator_profiles(emulators_dir)
    registry = load_data_dir_registry(platforms_dir)
    groups = group_identical_platforms(
        list_registered_platforms(platforms_dir),
        platforms_dir,
    )
    was_offline = packresolve._OFFLINE
    packresolve.set_offline(True)
    all_ok = True
    compared = 0
    try:
        for _members, platform in groups:
            config = load_platform_config(platform, platforms_dir)
            for label, narrowing in narrowed_variants(
                platform, config, profiles, platforms_dir, full,
            ):
                target = narrowing.get("target_name")
                target_cores = (
                    load_target_config(platform, target, platforms_dir) if target else None
                )
                record = generate_pack.PackRecord()
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    built = generate_pack.generate_pack(
                        platform, platforms_dir, db, "bios", "",
                        emulators_dir=emulators_dir, zip_contents=zip_contents,
                        data_registry=registry, emu_profiles=profiles,
                        target_cores=target_cores, offline=True, record=record,
                        **narrowing,
                    )
                    report = verify.verify_platform(
                        load_platform_config(platform, platforms_dir), db,
                        emulators_dir, profiles, target_cores=target_cores,
                        data_dir_registry=registry,
                        **{k: v for k, v in narrowing.items() if k != "target_name"},
                    ) if built else None
                compared += 1
                name = f"{platform} {label}"
                if report is None:
                    # The builder declines a system no core of the platform runs.
                    print(f"  {name}: the builder wrote no pack")
                    all_ok = False
                    continue
                credited = set(report["pack_destinations"])
                trees = set(record.trees) - credited
                written = {
                    m for m in record.members
                    if not _PACK_NOTES.search(m) and m not in trees
                }
                lines = _set_difference_lines(name, credited, written)
                if lines:
                    print("\n".join(lines))
                    all_ok = False
    finally:
        packresolve.set_offline(was_offline)
    scope = "full matrix" if full else "sampled"
    print(f"  {compared} narrowed platform packs compared ({scope}), "
          f"{'all equal' if all_ok else 'differences above'}")
    return all_ok


def split_differences(
    full: object, parts: dict[str, object], same_bytes: Callable[[str, str], bool],
) -> list[str]:
    """Where the --split parts of a pack, together, are not the full pack.

    A path in a part and not in the full pack, a path of the full pack in no
    part, and a path a part fills with other bytes than the full pack.
    """
    full_members = {m for m in full.members if not _PACK_NOTES.search(m)}
    union = {
        m for record in parts.values() for m in record.members
        if not _PACK_NOTES.search(m)
    }
    lines = [f"in a part, not in the full pack: {m}" for m in sorted(union - full_members)]
    lines += [f"in the full pack, in no part: {m}" for m in sorted(full_members - union)]
    lines += sorted({
        f"other bytes in {name}: {member}"
        for name, record in parts.items()
        for member, source in record.sources.items()
        if member in full.sources and not same_bytes(source, full.sources[member])
    })
    return lines


def check_split_packs(
    emulators_dir: str = "emulators", platforms_dir: str = "platforms",
    db_path: str = "database.json",
) -> bool:
    """Build each platform's --split parts in memory and compare them with
    the full pack: the parts must add up to it, path for path and byte for
    byte. Each part is a pack of its own and used to settle its paths alone:
    RetroDECK's parts carried bios/SGB1.sfc as a file and as a directory,
    RetroBat's 21 openmsx/ twins of openMSX/ files. Offline, as every
    comparison of this step.
    """
    import generate_pack  # noqa: PLC0415
    import packresolve  # noqa: PLC0415
    from common import (  # noqa: PLC0415
        build_zip_contents_index,
        group_identical_platforms,
        list_registered_platforms,
        load_data_dir_registry,
        load_database,
        load_emulator_profiles,
    )

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, split packs ---")
    db = load_database(db_path)
    zip_contents = build_zip_contents_index(db)
    profiles = load_emulator_profiles(emulators_dir)
    registry = load_data_dir_registry(platforms_dir)
    groups = group_identical_platforms(
        list_registered_platforms(platforms_dir),
        platforms_dir,
    )
    was_offline = packresolve._OFFLINE
    packresolve.set_offline(True)
    all_ok = True
    try:
        for _members, platform in groups:
            args = dict(
                emulators_dir=emulators_dir, zip_contents=zip_contents,
                data_registry=registry, emu_profiles=profiles, offline=True,
            )
            full = generate_pack.PackRecord()
            parts: dict[str, generate_pack.PackRecord] = {}
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                generate_pack.generate_pack(
                    platform, platforms_dir, db, "bios", "", record=full, **args,
                )
                generate_pack.generate_split_packs(
                    platform, platforms_dir, db, "bios", "", records=parts, **args,
                )
            lines = split_differences(full, parts, generate_pack._same_bytes)
            if lines:
                all_ok = False
                print(f"  {platform} --split: {len(lines)} differences")
                print("\n".join(f"    {line}" for line in lines[:20]))
    finally:
        packresolve.set_offline(was_offline)
    print(f"  {len(groups)} split platform packs compared, "
          f"{'all equal' if all_ok else 'differences above'}")
    return all_ok


class _Skipped:
    """A step that did not run. Truthy, so it never fails the pipeline, and
    distinct, so the summary does not report it as work that was done."""

    def __bool__(self) -> bool:
        return True

    def __repr__(self) -> str:
        return "SKIPPED"


SKIPPED = _Skipped()


def integrity_command(args: argparse.Namespace) -> list[str]:
    """Step 6: check the packs step 4 built, under the same expectation."""
    cmd = [
        sys.executable, "scripts/generate_pack.py", "--all", "--verify-packs",
        "--output-dir", args.output_dir,
    ]
    # Without the target a targeted run reported every system the target
    # removed as missing from a pack that was exactly right. Without
    # --all-variants the five narrowed packs were never opened, and an empty
    # _Platform pack passed.
    if args.target:
        cmd.extend(["--target", args.target])
    if args.all_variants:
        cmd.append("--all-variants")
    return cmd


def _refuse_unapplied_flags(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    """A flag the run would drop is refused before any step.

    --all-variants builds every source itself, so a --source beside it is
    dropped; --skip-packs builds none, so both are, and step 5 does not run
    for --full-narrowings to widen, nor does it without a full pack.
    """
    # --source defaults to None so a typed `--source full` is seen: compared
    # with its default value, it went through beside the modes that refuse it.
    source_given = args.source is not None
    if args.all_variants and source_given:
        parser.error("--source is incompatible with --all-variants")
    if args.skip_packs:
        for flag, on in (("--source", source_given),
                         ("--all-variants", args.all_variants),
                         ("--full-narrowings", args.full_narrowings)):
            if on:
                parser.error(f"{flag} is incompatible with --skip-packs")
    # Step 5 compares the full pack, and --source platform or truth builds
    # none: the comparison is skipped and the flag had no effect.
    if args.full_narrowings and source_given and args.source != "full":
        parser.error(f"--full-narrowings is incompatible with --source {args.source}")
    if args.source is None:
        args.source = "full"


def _refuse_offline_without_caches(
    parser: argparse.ArgumentParser, args: argparse.Namespace, platforms_dir: str = "platforms",
) -> None:
    """An offline run that builds packs needs the data directories cached.

    On a fresh clone none is: --offline skips the refresh, and the run went
    through the database, verify and every pack before failing at the end
    of the build. Only an empty cache is refused here: with some cached, the
    packs decide which ones they need and the build names the rest.
    """
    if not args.offline or args.skip_packs:
        return
    registry = load_data_dir_registry(platforms_dir)
    if registry and not any(os.path.isdir(e.get("local_cache") or "") for e in registry.values()):
        parser.error(
            "no data directory is cached and --offline skips their refresh: run "
            "python scripts/refresh_data_dirs.py once, or drop --offline"
        )


def _refuse_offline_export_without_originals(
    parser: argparse.ArgumentParser, args: argparse.Namespace,
    cache: str = ".cache/upstream-native",
) -> None:
    """An offline run with --with-export needs each patched file cached.

    Seven formats carry code, so step 2e patches the platform's own file,
    which --offline does not fetch. On a fresh clone the database, verify
    and the truth model were built before step 2e failed on every one.
    """
    if not (args.offline and args.with_export):
        return
    from exporter import discover_exporters  # noqa: PLC0415

    lacking = sorted(
        name for name, exporter in discover_exporters().items()
        if exporter.needs_original() and not any(Path(cache, name).glob("*"))
    )
    if lacking:
        parser.error(
            f"--with-export patches each platform's own file, and {cache}/ holds none "
            f"for {', '.join(lacking)}: run python scripts/export_native.py --all "
            "--refresh-cache once, or drop --offline"
        )


def _truth_steps(args: argparse.Namespace, results: dict) -> bool:
    """Steps 2c to 2e: truth model, its diff, the native export."""
    all_ok = True
    # Step 2c: Generate truth YAMLs
    # A targeted run writes each platform's model under the target as that
    # platform files it, and the diff is told the target and reads the same place.
    truth_dir = Path(args.output_dir) / "truth"

    if args.with_truth or args.with_export:
        truth_cmd = [
            sys.executable,
            "scripts/generate_truth.py",
            "--all",
            "--output-dir",
            str(Path(args.output_dir) / "truth"),
        ]
        if args.target:
            truth_cmd.extend(["--target", args.target])
        ok, _ = run(truth_cmd, STEP_LABELS["generate_truth"])
        # A native file is one per platform, never per target: the export
        # corrects it against the full model, which a targeted run does not
        # write.
        if ok and args.with_export and args.target:
            ok, _ = run(truth_cmd[:-2], "2c generate truth (export model)")
        results["generate_truth"] = ok
        all_ok = all_ok and ok
    else:
        results["generate_truth"] = SKIPPED

    # Step 2d: Diff truth vs scraped
    if args.with_truth or args.with_export:
        diff_cmd = [sys.executable, "scripts/diff_truth.py", "--all"]
        diff_cmd.extend(["--truth-dir", str(truth_dir)])
        if args.target:
            diff_cmd.extend(["--target", args.target])
        ok, _ = run(diff_cmd, STEP_LABELS["diff_truth"])
        results["diff_truth"] = ok
        all_ok = all_ok and ok
    else:
        results["diff_truth"] = SKIPPED

    # Step 2e: Export native formats
    if args.with_export:
        export_cmd = [
            sys.executable,
            "scripts/export_native.py",
            "--all",
            # exports/ is committed with the code, like README.md and
            # install/: written under the pack directory it went stale on
            # every green run.
            "--truth-dir",
            str(Path(args.output_dir) / "truth"),
        ]
        # Seven of the formats carry code, so the export patches the
        # platform's own file rather than regenerating it. Offline that
        # file has to be in the cache already.
        if not args.offline:
            export_cmd.append("--fetch")
        ok, _ = run(export_cmd, STEP_LABELS["export_native"])
        results["export_native"] = ok
        all_ok = all_ok and ok
    else:
        results["export_native"] = SKIPPED

    return all_ok


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Run the full retrobios pipeline")
    parser.add_argument(
        "--skip-packs",
        action="store_true",
        help="Skip steps 4, 4b, 4c, 5 and 6: packs, manifests and their checks. "
        "Step 4d still gates the run, step 4e still rewrites install/games/, and "
        "steps 7 to 8b rewrite README.md and the site unless --skip-docs is given",
    )
    parser.add_argument(
        "--skip-docs", action="store_true",
        help="Skip steps 7, 8 and 8b: README, installer page and site"
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="No network: skips steps 2 to 2b2 and packs only the release "
        "assets already in .cache/large/"
    )
    parser.add_argument(
        "--output-dir",
        help="Pack output directory (default: dist/ at the repository root)",
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--source", choices=["platform", "truth", "full"], default=None,
        help="packs to build: the platform list, the profiles, or both (default: "
             "full)",
    )
    parser.add_argument(
        "--all-variants", action="store_true",
        help="Build the six source x required packs of each platform; "
        "not with --source or --skip-packs",
    )
    parser.add_argument(
        "--full-narrowings", action="store_true",
        help="Step 5 compares every region, target and system of each "
        "platform, and every region of each emulator and system pack, not a "
        "sample of three (about 25 minutes)",
    )
    parser.add_argument(
        "--check-buildbot",
        action="store_true",
        help="Check buildbot system directory for changes",
    )
    parser.add_argument(
        "--with-truth",
        action="store_true",
        help="Generate truth YAMLs and diff against scraped",
    )
    parser.add_argument(
        "--with-export",
        action="store_true",
        help="Export native formats (implies --with-truth)",
    )
    args = parser.parse_args()
    _refuse_unapplied_flags(parser, args)
    _refuse_offline_without_caches(parser, args)
    _refuse_offline_export_without_originals(parser, args)
    if not args.offline:
        # Read once and put in the environment every step inherits: the
        # scrapers and refresh_data_dirs went anonymous unless the user had
        # exported GITHUB_TOKEN by hand, though gh was logged in.
        github_token()
    args.output_dir = _output_dir(args.output_dir)

    # A second run on the same output directory is refused before any work:
    # the database rebuild alone takes minutes, and the reader holding the
    # directory would otherwise see the answer only after all of it. The
    # hold lasts until this process exits: taken step by step, it let another
    # run purge the packs between the build and the integrity check, which
    # then reported every platform SKIP and passed.
    # database.json, install/, README.md, CONTRIBUTING.md and website/ sit at
    # fixed paths (artifacts.REPOSITORY_OUTPUTS), so
    # every run holds them too: a run on a scratch --output-dir otherwise
    # rewrote them beside the run on dist/.
    held = contextlib.ExitStack()
    try:
        root = str(Path(__file__).resolve().parent.parent)
        held.enter_context(hold_repository_outputs(root))
        # Its steps write database.json, install/ and README.md themselves,
        # and take the same lock to do so.
        held.enter_context(publish_hold(root))
        if not args.skip_packs:
            held.enter_context(hold_artifact_lock(args.output_dir))
    except ArtifactLockBusy as exc:
        held.close()
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    all_ok = True
    total_start = time.monotonic()
    results = StepResults(total_start)

    # Step 0: the schema check PR validation runs. Without it a profile with
    # `cores: [81]` unquoted passed the whole pipeline and failed CI on push.
    # jsonschema is tooling only, so its absence skips the step.
    if importlib.util.find_spec("jsonschema") is None:
        # The skip names the install and what still runs the check, or a
        # contributor read SKIPPED, then COMPLETE, and met the failure on push.
        skip_notice(
            "validate_schemas",
            "jsonschema not installed. PR validation runs this check: "
            'pip install "jsonschema[format-nongpl]"',
        )
        results["validate_schemas"] = SKIPPED
    else:
        ok, _ = run(
            [sys.executable, "scripts/validate_schemas.py", "--source-only"],
            STEP_LABELS["validate_schemas"],
        )
        results["validate_schemas"] = ok
        all_ok = all_ok and ok

    # Step 1: Generate database
    ok, out = run(
        [
            sys.executable,
            "scripts/generate_db.py",
            "--force",
            "--bios-dir",
            "bios",
            "--output",
            "database.json",
        ],
        STEP_LABELS["generate_db"],
    )
    results["generate_db"] = ok
    if not ok:
        print("\nDatabase generation failed, aborting.")
        sys.exit(1)

    # Step 1b: Dump-catalog coverage (offline, reads provenance/ snapshots),
    # and which missing dumps the collection already produces: recorded in
    # derivable.json, which the site reads instead of rereading bios/.
    ok, _ = run(
        [sys.executable, "scripts/provenance_report.py", "--derive",
         "--write-derivable", "derivable.json"],
        STEP_LABELS["provenance"],
    )
    results["provenance"] = ok
    all_ok = all_ok and ok

    # Step 1c: Which emulator version each arcade archive corresponds to, and
    # which pinned archive the collection could rebuild from ROMs it holds.
    # Read-only: writing reconstructions is an explicit --write invocation.
    ok, out = run(
        [sys.executable, "scripts/romset_recipes.py"],
        STEP_LABELS["romset_recipes"],
    )
    # A recipe for every archive database.json lists (recipes/archives.json):
    # only an archive whose sha1 moved is read again, so the step costs the
    # archives added since the last run.
    captured, _ = run(
        [sys.executable, "scripts/romset_recipes.py", "--capture"],
        f"{STEP_LABELS['romset_recipes']} (archive recipes)",
    )
    ok = ok and captured
    results["romset_recipes"] = ok
    all_ok = all_ok and ok

    # Step 2: Refresh data directories
    if not args.offline:
        ok, out = run(
            [sys.executable, "scripts/refresh_data_dirs.py"],
            STEP_LABELS["refresh_data"],
        )
        results["refresh_data"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("refresh_data", "--offline")
        results["refresh_data"] = SKIPPED

    # Step 2a: Refresh MAME BIOS hashes
    if not args.offline:
        ok, _ = run(
            [sys.executable, "-m", "scripts.scraper.mame_hash_scraper"],
            STEP_LABELS["mame_hashes"],
        )
        results["mame_hashes"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("mame_hashes", "--offline")
        results["mame_hashes"] = SKIPPED

    # Step 2a2: Refresh FBNeo BIOS hashes
    if not args.offline:
        ok, _ = run(
            [sys.executable, "-m", "scripts.scraper.fbneo_hash_scraper"],
            STEP_LABELS["fbneo_hashes"],
        )
        results["fbneo_hashes"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("fbneo_hashes", "--offline")
        results["fbneo_hashes"] = SKIPPED

    # Step 2b: Check buildbot system directory (non-blocking)
    if args.check_buildbot and not args.offline:
        ok, _ = run(
            [sys.executable, "scripts/check_buildbot_system.py"],
            STEP_LABELS["check_buildbot"],
        )
        results["check_buildbot"] = ok
    else:
        if args.check_buildbot:
            skip_notice("check_buildbot", "--offline")
        results["check_buildbot"] = SKIPPED

    # Step 2b2: The release must serve the bytes the manifests describe. The
    # installer compares Content-Length with the manifest size, so an asset
    # uploaded before its local file was rebuilt fails every install of it.
    if not args.offline:
        ok, _ = run(
            [sys.executable, "scripts/check_release_assets.py"],
            STEP_LABELS["check_release_assets"],
        )
        results["check_release_assets"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("check_release_assets", "--offline")
        results["check_release_assets"] = SKIPPED

    all_ok = _truth_steps(args, results) and all_ok

    # Every step from here reads the data directory trees: verify, the packs,
    # the manifests and the integrity check. Held shared until the run ends,
    # a refresh from another session waits instead of swapping a tree
    # between the packs and the manifests, which would then describe two
    # revisions of it. Taken after step 2, whose own refresh needs them
    # exclusive.
    hold_data_dirs(held, load_data_dir_registry("platforms"))

    # Step 3: Verify. The paths each pack holds by this report go to a file
    # step 5 compares with the archives.
    scratch = Path(__file__).resolve().parent.parent / "tmp"
    scratch.mkdir(exist_ok=True)
    fd, destinations_file = tempfile.mkstemp(
        prefix="verify-destinations.", suffix=".json", dir=scratch
    )
    os.close(fd)
    atexit.register(Path(destinations_file).unlink, missing_ok=True)
    verify_cmd = [
        sys.executable, "scripts/verify.py", "--all", "--strict",
        "--destinations", destinations_file,
    ]
    if args.target:
        verify_cmd.extend(["--target", args.target])
    if args.offline:
        # The packs of step 4 fetch no release asset: a missing one is
        # missing on both sides.
        verify_cmd.append("--offline")
    ok, verify_output = run(verify_cmd, STEP_LABELS["verify"])
    results["verify"] = ok
    all_ok = all_ok and ok

    # Step 3a: One content answering to two identities. Walks the tree rather
    # than the index, which keeps a single path per content and therefore
    # cannot see a file copied under another machine's name.
    ok, _ = run(
        [sys.executable, "scripts/identity.py", "--strict"],
        STEP_LABELS["identity"],
    )
    results["identity"] = ok
    all_ok = all_ok and ok

    # Step 3b: Destinations both layers claim, and how each was settled. The
    # ones the pack settles by itself must stay at zero cost. The rest name an
    # upstream declaration no build can repair, so this reports and never gates.
    # A crash is not a report: without --strict slots.py exits 0 on every
    # conflict, so a non-zero code means it never finished reading.
    # The same cores verify judged: without the target the arbitration of a
    # targeted run judged cores the target does not ship.
    slots_cmd = [sys.executable, "scripts/slots.py"]
    if args.target:
        slots_cmd.extend(["--target", args.target])
    ok, _ = run(slots_cmd, "3b slot arbitration")
    results["slots"] = ok
    all_ok &= ok

    # Step 4: Generate packs
    pack_output = ""
    if not args.skip_packs:
        # Purge stale packs: leftover ZIPs from previous builds would be
        # picked up by pack verification and shipped in releases.
        out_dir = Path(args.output_dir)
        if out_dir.is_dir():
            try:
                with artifact_lock(str(out_dir)):
                    stale = [
                        p for p in out_dir.iterdir()
                        if p.is_file() and (
                            p.suffix == ".zip"
                            or ".zip." in p.name
                            or p.name == "SHA256SUMS.txt"
                        )
                    ]
                    for p in stale:
                        p.unlink()
                    if stale:
                        print(f"Purged {len(stale)} stale pack file(s) from {out_dir}/")
            except ArtifactLockBusy as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                sys.exit(1)

        pack_cmd = [
            sys.executable,
            "scripts/generate_pack.py",
            "--all",
            "--output-dir",
            args.output_dir,
        ]
        if args.offline:
            pack_cmd.append("--offline")
        else:
            # Step 2 refreshed the trees once: refreshing again here let the
            # pack and the manifest describe two revisions of a moving tree.
            pack_cmd.append("--no-refresh-data")
        if args.target:
            pack_cmd.extend(["--target", args.target])
        if args.source != "full":
            pack_cmd.extend(["--source", args.source])
        if args.all_variants:
            pack_cmd.append("--all-variants")
        ok, pack_output = run(pack_cmd, STEP_LABELS["generate_packs"])
        results["generate_packs"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_packs", "--skip-packs")
        results["generate_packs"] = SKIPPED

    # Step 4b: Generate install manifests
    if not args.skip_packs:
        manifest_cmd = [
            sys.executable,
            "scripts/generate_pack.py",
            "--all",
            "--manifest",
            "--output-dir",
            "install",
        ]
        if args.offline:
            manifest_cmd.append("--offline")
        else:
            # Step 2 refreshed the trees once: refreshing again here let the
            # pack and the manifest describe two revisions of a moving tree.
            manifest_cmd.append("--no-refresh-data")
        # No --target here: install/ holds the published lists, and every
        # reader (site picker, release check, record) takes each file there
        # as a whole platform. The per-target core lists are step 4c.
        ok, _ = run(manifest_cmd, STEP_LABELS["generate_manifests"])
        results["generate_manifests"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_manifests", "--skip-packs")
        results["generate_manifests"] = SKIPPED

    # Step 4c: Generate target manifests
    if not args.skip_packs:
        target_cmd = [
            sys.executable,
            "scripts/generate_pack.py",
            "--manifest-targets",
            "--output-dir",
            "install/targets",
        ]
        ok, _ = run(target_cmd, STEP_LABELS["generate_target_manifests"])
        results["generate_target_manifests"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_target_manifests", "--skip-packs")
        results["generate_target_manifests"] = SKIPPED

    # Step 4d: A collected copy that only an emulator's own install provides.
    # Packs leave such files out, so a copy nothing else asks for is weight
    # the collection carries for nobody. Read after the manifests, which say
    # what an installation ships.
    ok, _ = run(
        [sys.executable, "scripts/bundled_only.py", "--strict"],
        STEP_LABELS["bundled_only"],
    )
    results["bundled_only"] = ok
    all_ok &= ok

    # Step 4e: What the installer reads for the games on a card: rom folders,
    # game catalogs, header and region rules, arcade parents, and the
    # fallback sets, which read the install lists. Runs under --skip-packs
    # too, on the committed lists, so a rescrape of the rom folders or a DAT
    # import reaches install/games/ in the same run.
    ok, _ = run(
        [sys.executable, "scripts/generate_games_index.py", "--quiet"],
        STEP_LABELS["games_index"],
    )
    results["games_index"] = ok
    all_ok &= ok

    # Step 5: Consistency check. verify describes the full pack, and a run that
    # built only a reduced one (--source platform or truth) has nothing to
    # compare it with, and says so instead of failing on an empty parse.
    full_pack_built = args.source == "full" or args.all_variants
    if pack_output and verify_output and not full_pack_built:
        skip_notice("consistency", "no full pack built")
        results["consistency"] = SKIPPED
    elif pack_output and verify_output:
        ok = check_consistency(
            verify_output, pack_output,
            release_pack_keys(),
        )
        # Counts can agree while the paths differ, both ways at once.
        ok = check_pack_destinations(destinations_file, pack_output) and ok
        ok = check_emulator_packs(full=args.full_narrowings) and ok
        ok = check_narrowed_packs(full=args.full_narrowings) and ok
        ok = check_split_packs() and ok
        print(
            f"--- {step_title(STEP_LABELS['consistency'])}, counts and paths: "
            f"{'OK' if ok else 'FAILED'} ---"
        )
        results["consistency"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("consistency")
        results["consistency"] = SKIPPED

    # Step 6: Pack integrity (extract + hash verification)
    if not args.skip_packs and not full_pack_built:
        # The check reads the full pack's name, while a reduced pack holds fewer
        # files than the platform declares by design.
        skip_notice("pack_integrity", "no full pack built")
        results["pack_integrity"] = SKIPPED
    elif not args.skip_packs:
        ok, _ = run(integrity_command(args), STEP_LABELS["pack_integrity"])
        results["pack_integrity"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("pack_integrity", "--skip-packs")
        results["pack_integrity"] = SKIPPED

    # Step 7: Generate README
    if not args.skip_docs:
        ok, _ = run(
            [
                sys.executable,
                "scripts/generate_readme.py",
                "--db",
                "database.json",
                "--platforms-dir",
                "platforms",
            ],
            STEP_LABELS["generate_readme"],
        )
        # The run samples of wiki/installer.md, printed by install.py from
        # the manifests step 4b just wrote.
        doc_ok, _ = run([sys.executable, "scripts/generate_installer_doc.py"],
                        "7 generate installer page")
        # The verify excerpt of wiki/reading-reports.md, from this run's data.
        excerpt_ok, _ = run([sys.executable, "scripts/generate_report_excerpt.py"],
                            "7 generate report excerpt")
        ok = ok and doc_ok and excerpt_ok
        results["generate_readme"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_readme", "--skip-docs")
        results["generate_readme"] = SKIPPED

    # Step 8: Generate site pages
    if not args.skip_docs:
        ok, _ = run(
            [sys.executable, "scripts/generate_site.py"],
            STEP_LABELS["generate_site"],
        )
        results["generate_site"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_site", "--skip-docs")
        results["generate_site"] = SKIPPED

    # Step 8b: the render the site deploy runs. Generating the pages without
    # rendering them let 20 pages with duplicate ids through to CI.
    if args.skip_docs:
        skip_notice("render_site", "--skip-docs")
        results["render_site"] = SKIPPED
    elif shutil.which("npm") is None or not Path("website/node_modules").is_dir():
        skip_notice("render_site", "Node not set up: npm ci --prefix website")
        results["render_site"] = SKIPPED
    else:
        # Starlight's link check runs inside the build and fails it.
        ok, _ = run(["npm", "run", "build", "--prefix", "website"], STEP_LABELS["render_site"])
        if ok:
            ok, _ = run([sys.executable, "scripts/validate_site.py", "--site-dir", "website/dist"],
                        "8b validate site")
        results["render_site"] = ok
        all_ok = all_ok and ok

    # Summary
    total_elapsed = time.monotonic() - total_start
    print(f"\n{'=' * 60}")
    warned = []
    for step, outcome in results.items():
        # The number finds the step's lines in the log, the key is the
        # name a caller reading the results knows it by.
        number = step_number(step)
        if outcome is SKIPPED:
            print(f"  {number:<4} {step:.<40} SKIPPED")
            continue
        label = "OK" if outcome else "FAILED"
        if not outcome and step in NON_BLOCKING:
            # Printed FAILED right above "Pipeline COMPLETE", it read as a
            # contradiction: the step reports, it does not stop the run.
            label = "WARN"
            warned.append(step)
        print(f"  {number:<4} {step:.<40} {label:<7}{results.seconds[step]:>8.1f}s")
    print(f"  {'':<4} {'total':.<40} {'':<7}{total_elapsed:>8.1f}s")
    print(f"{'=' * 60}")
    print(f"  Pipeline {'COMPLETE' if all_ok else 'FINISHED WITH ERRORS'}")
    if warned:
        print(f"  {', '.join(warned)} reported a difference, which does not fail the run")
    print(f"{'=' * 60}")
    held.close()
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
