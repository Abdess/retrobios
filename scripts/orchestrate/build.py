"""Steps 3 to 4e: verify and its arbitrations, the packs and manifests, the install indexes."""

from __future__ import annotations

import argparse
import atexit
import contextlib
import os
import sys
import tempfile
from pathlib import Path

from core.artifacts import ArtifactLockBusy, artifact_lock
from core.paths import PLATFORMS_DIR, REPO_ROOT
from model.registry import load_data_dir_registry
from orchestrate import runner
from orchestrate.labels import STEP_LABELS, skip_notice
from orchestrate.results import SKIPPED
from packs.datadirs import hold_data_dirs


def verify_steps(
    args: argparse.Namespace, results: dict, held: contextlib.ExitStack
) -> tuple[bool, str, str]:
    """Steps 3 to 3b: verify, identities, slots.

    Returns whether they passed, verify's output and the file of the paths
    each pack holds by its report.
    """
    all_ok = True
    # Every step from here reads the data directory trees: verify, the packs,
    # the manifests and the integrity check. Held shared until the run ends,
    # a refresh from another session waits instead of swapping a tree
    # between the packs and the manifests, which would then describe two
    # revisions of it. Taken after step 2, whose own refresh needs them
    # exclusive.
    hold_data_dirs(held, load_data_dir_registry(PLATFORMS_DIR))

    # Step 3: Verify. The paths each pack holds by this report go to a file
    # step 5 compares with the archives.
    scratch = REPO_ROOT / "tmp"
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
    ok, verify_output = runner.run(verify_cmd, STEP_LABELS["verify"])
    results["verify"] = ok
    all_ok = all_ok and ok

    # Step 3a: One content answering to two identities. Walks the tree rather
    # than the index, which keeps a single path per content and therefore
    # cannot see a file copied under another machine's name.
    ok, _ = runner.run(
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
    ok, _ = runner.run(slots_cmd, "3b slot arbitration")
    results["slots"] = ok
    all_ok &= ok
    return all_ok, verify_output, destinations_file


def purge_stale_packs(output_dir: str) -> None:
    """Remove the packs of earlier builds from the output directory."""
    # Purge stale packs: leftover ZIPs from previous builds would be
    # picked up by pack verification and shipped in releases.
    out_dir = Path(output_dir)
    if not out_dir.is_dir():
        return
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


def pack_command(args: argparse.Namespace) -> list[str]:
    """The step 4 command: every platform's pack."""
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
    return pack_cmd


def pack_steps(args: argparse.Namespace, results: dict) -> tuple[bool, str]:
    """Steps 4 to 4c: packs, install manifests, target manifests.

    Returns whether they passed and the pack build's output.
    """
    all_ok = True
    # Step 4: Generate packs
    pack_output = ""
    if not args.skip_packs:
        purge_stale_packs(args.output_dir)
        ok, pack_output = runner.run(pack_command(args), STEP_LABELS["generate_packs"])
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
        ok, _ = runner.run(manifest_cmd, STEP_LABELS["generate_manifests"])
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
        ok, _ = runner.run(target_cmd, STEP_LABELS["generate_target_manifests"])
        results["generate_target_manifests"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("generate_target_manifests", "--skip-packs")
        results["generate_target_manifests"] = SKIPPED
    return all_ok, pack_output


def index_steps(results: dict) -> bool:
    """Steps 4d and 4e: bundled-only copies, the games index."""
    all_ok = True
    # Step 4d: A collected copy that only an emulator's own install provides.
    # Packs leave such files out, so a copy nothing else asks for is weight
    # the collection carries for nobody. Read after the manifests, which say
    # what an installation ships.
    ok, _ = runner.run(
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
    ok, _ = runner.run(
        [sys.executable, "scripts/generate_games_index.py", "--quiet"],
        STEP_LABELS["games_index"],
    )
    results["games_index"] = ok
    all_ok &= ok
    return all_ok
