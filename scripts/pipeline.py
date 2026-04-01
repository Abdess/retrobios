#!/usr/bin/env python3
"""Run the full retrobios pipeline.

Steps:
  1. generate_db.py --force     (rebuild database.json from bios/)
  2. refresh_data_dirs.py       (update Dolphin Sys, PPSSPP, etc.)
  3. verify.py --all            (check all platforms)
  4. generate_pack.py --all     (build ZIP packs)
  4b. generate install manifests
  4c. generate target manifests
  5. consistency check          (verify counts == pack counts)
  8. generate_readme.py         (rebuild README.md + CONTRIBUTING.md)
  9. generate_site.py           (rebuild MkDocs pages)

Usage:
    python scripts/pipeline.py                    # active platforms
    python scripts/pipeline.py --include-archived # all platforms
    python scripts/pipeline.py --skip-packs       # steps 1-3 only
    python scripts/pipeline.py --skip-docs        # skip steps 8-9
    python scripts/pipeline.py --offline          # skip step 2
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def run(cmd: list[str], label: str) -> tuple[bool, str]:
    """Run a command. Returns (success, captured_output)."""
    print(f"\n--- {label} ---", flush=True)
    start = time.monotonic()
    repo_root = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_root)
    elapsed = time.monotonic() - start

    output = result.stdout
    if result.stderr:
        output += result.stderr

    ok = result.returncode == 0
    print(output, end="")
    print(f"--- {label}: {'OK' if ok else 'FAILED'} ({elapsed:.1f}s) ---")
    return ok, output


def parse_verify_counts(output: str) -> dict[str, tuple[int, int]]:
    """Extract per-group OK/total from verify output.

    Matches: "Label: X/Y OK ..." or "Label: X/Y present ..."
    Returns {group_label: (ok, total)}.
    """
    import re
    counts = {}
    for line in output.splitlines():
        m = re.match(r"^(.+?):\s+(\d+)/(\d+)\s+(OK|present)", line)
        if m:
            label = m.group(1).strip()
            ok, total = int(m.group(2)), int(m.group(3))
            for name in label.split(" / "):
                counts[name.strip()] = (ok, total)
    return counts


def parse_pack_counts(output: str) -> dict[str, tuple[int, int]]:
    """Extract per-pack OK/total from generate_pack output.

    Returns {pack_label: (ok, total)}.
    """
    import re
    counts = {}
    current_label = ""
    for line in output.splitlines():
        m = re.match(r"Generating (?:shared )?pack for (.+)\.\.\.", line)
        if m:
            current_label = m.group(1)
            continue
        if "files packed" not in line:
            continue
        # New format: "622 files packed (359 baseline + 263 from cores), 358/359 files OK"
        base_m = re.search(r"\((\d+) baseline", line)
        ok_m = re.search(r"(\d+)/(\d+) files OK", line)
        if base_m and ok_m:
            baseline = int(base_m.group(1))
            ok, total = int(ok_m.group(1)), int(ok_m.group(2))
            counts[current_label] = (ok, total)
        elif ok_m:
            # Fallback: old format without baseline
            ok, total = int(ok_m.group(1)), int(ok_m.group(2))
            counts[current_label] = (ok, total)
    return counts


def check_consistency(verify_output: str, pack_output: str) -> bool:
    """Verify that check counts match between verify and pack for each platform."""
    v = parse_verify_counts(verify_output)
    p = parse_pack_counts(pack_output)

    print("\n--- 5/8 consistency check ---")
    all_ok = True

    for v_label, (v_ok, v_total) in sorted(v.items()):
        # Match by name overlap (handles "Lakka + RetroArch" vs "Lakka / RetroArch")
        p_match = None
        for p_label in p:
            v_names = {n.strip().lower() for n in v_label.split("/")}
            p_names = {n.strip().lower() for n in p_label.replace("+", "/").split("/")}
            if v_names & p_names:
                p_match = p_label
                break

        if p_match:
            p_ok, p_total = p[p_match]
            if v_total != p_total:
                print(f"  {v_label}: MISMATCH total verify {v_total} != pack {p_total}")
                all_ok = False
            elif p_ok < v_ok:
                print(f"  {v_label}: MISMATCH pack {p_ok} OK < verify {v_ok} OK (/{v_total})")
                all_ok = False
            elif p_ok == v_ok:
                print(f"  {v_label}: verify {v_ok}/{v_total} == pack {p_ok}/{p_total} OK")
            else:
                print(f"  {v_label}: verify {v_ok}/{v_total}, pack {p_ok}/{p_total} OK (pack resolves more)")
        else:
            print(f"  {v_label}: {v_ok}/{v_total} (no separate pack)")

    status = "OK" if all_ok else "FAILED"
    print(f"--- consistency check: {status} ---")
    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Run the full retrobios pipeline")
    parser.add_argument("--include-archived", action="store_true",
                        help="Include archived platforms")
    parser.add_argument("--skip-packs", action="store_true",
                        help="Only regenerate DB and verify, skip pack generation")
    parser.add_argument("--skip-docs", action="store_true",
                        help="Skip README and site generation")
    parser.add_argument("--offline", action="store_true",
                        help="Skip data directory refresh")
    parser.add_argument("--output-dir", default="dist",
                        help="Pack output directory (default: dist/)")
    # --include-extras is now a no-op: core requirements are always included
    parser.add_argument("--include-extras", action="store_true",
                        help="(no-op) Core requirements are always included")
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument("--check-buildbot", action="store_true",
                        help="Check buildbot system directory for changes")
    parser.add_argument("--with-truth", action="store_true",
                        help="Generate truth YAMLs and diff against scraped")
    parser.add_argument("--with-export", action="store_true",
                        help="Export native formats (implies --with-truth)")
    args = parser.parse_args()

    results = {}
    all_ok = True
    total_start = time.monotonic()

    # Step 1: Generate database
    ok, out = run(
        [sys.executable, "scripts/generate_db.py", "--force",
         "--bios-dir", "bios", "--output", "database.json"],
        "1/8 generate database",
    )
    results["generate_db"] = ok
    if not ok:
        print("\nDatabase generation failed, aborting.")
        sys.exit(1)

    # Step 2: Refresh data directories
    if not args.offline:
        ok, out = run(
            [sys.executable, "scripts/refresh_data_dirs.py"],
            "2/8 refresh data directories",
        )
        results["refresh_data"] = ok
    else:
        print("\n--- 2/8 refresh data directories: SKIPPED (--offline) ---")
        results["refresh_data"] = True

    # Step 2a: Refresh MAME BIOS hashes
    if not args.offline:
        ok, _ = run(
            [sys.executable, "-m", "scripts.scraper.mame_hash_scraper"],
            "2a refresh MAME hashes",
        )
        results["mame_hashes"] = ok
    else:
        print("\n--- 2a refresh MAME hashes: SKIPPED (--offline) ---")
        results["mame_hashes"] = True

    # Step 2a2: Refresh FBNeo BIOS hashes
    if not args.offline:
        ok, _ = run(
            [sys.executable, "-m", "scripts.scraper.fbneo_hash_scraper"],
            "2a2 refresh FBNeo hashes",
        )
        results["fbneo_hashes"] = ok
    else:
        print("\n--- 2a2 refresh FBNeo hashes: SKIPPED (--offline) ---")
        results["fbneo_hashes"] = True

    # Step 2b: Check buildbot system directory (non-blocking)
    if args.check_buildbot and not args.offline:
        ok, _ = run(
            [sys.executable, "scripts/check_buildbot_system.py"],
            "2b check buildbot system",
        )
        results["check_buildbot"] = ok
    elif args.check_buildbot:
        print("\n--- 2b check buildbot system: SKIPPED (--offline) ---")

    # Step 2c: Generate truth YAMLs
    if args.with_truth or args.with_export:
        truth_cmd = [sys.executable, "scripts/generate_truth.py", "--all",
                     "--output-dir", str(Path(args.output_dir) / "truth")]
        if args.include_archived:
            truth_cmd.append("--include-archived")
        if args.target:
            truth_cmd.extend(["--target", args.target])
        ok, _ = run(truth_cmd, "2c generate truth")
        results["generate_truth"] = ok
        all_ok = all_ok and ok
    else:
        results["generate_truth"] = True

    # Step 2d: Diff truth vs scraped
    if args.with_truth or args.with_export:
        diff_cmd = [sys.executable, "scripts/diff_truth.py", "--all"]
        if args.include_archived:
            diff_cmd.append("--include-archived")
        diff_cmd.extend(["--truth-dir", str(Path(args.output_dir) / "truth")])
        ok, _ = run(diff_cmd, "2d diff truth")
        results["diff_truth"] = ok
        all_ok = all_ok and ok
    else:
        results["diff_truth"] = True

    # Step 2e: Export native formats
    if args.with_export:
        export_cmd = [sys.executable, "scripts/export_native.py", "--all",
                      "--output-dir", str(Path(args.output_dir) / "upstream"),
                      "--truth-dir", str(Path(args.output_dir) / "truth")]
        if args.include_archived:
            export_cmd.append("--include-archived")
        ok, _ = run(export_cmd, "2e export native")
        results["export_native"] = ok
        all_ok = all_ok and ok
    else:
        results["export_native"] = True

    # Step 3: Verify
    verify_cmd = [sys.executable, "scripts/verify.py", "--all"]
    if args.include_archived:
        verify_cmd.append("--include-archived")
    if args.target:
        verify_cmd.extend(["--target", args.target])
    ok, verify_output = run(verify_cmd, "3/8 verify all platforms")
    results["verify"] = ok
    all_ok = all_ok and ok

    # Step 4: Generate packs
    pack_output = ""
    if not args.skip_packs:
        pack_cmd = [
            sys.executable, "scripts/generate_pack.py", "--all",
            "--output-dir", args.output_dir,
        ]
        if args.include_archived:
            pack_cmd.append("--include-archived")
        if args.offline:
            pack_cmd.append("--offline")
        if args.include_extras:
            pack_cmd.append("--include-extras")
        if args.target:
            pack_cmd.extend(["--target", args.target])
        ok, pack_output = run(pack_cmd, "4/8 generate packs")
        results["generate_packs"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 4/8 generate packs: SKIPPED (--skip-packs) ---")
        results["generate_packs"] = True

    # Step 4b: Generate install manifests
    if not args.skip_packs:
        manifest_cmd = [
            sys.executable, "scripts/generate_pack.py", "--all",
            "--manifest", "--output-dir", "install",
        ]
        if args.include_archived:
            manifest_cmd.append("--include-archived")
        if args.offline:
            manifest_cmd.append("--offline")
        if args.target:
            manifest_cmd.extend(["--target", args.target])
        ok, _ = run(manifest_cmd, "4b/8 generate install manifests")
        results["generate_manifests"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 4b/8 generate install manifests: SKIPPED (--skip-packs) ---")
        results["generate_manifests"] = True

    # Step 4c: Generate target manifests
    if not args.skip_packs:
        target_cmd = [
            sys.executable, "scripts/generate_pack.py",
            "--manifest-targets", "--output-dir", "install/targets",
        ]
        ok, _ = run(target_cmd, "4c/8 generate target manifests")
        results["generate_target_manifests"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 4c/8 generate target manifests: SKIPPED (--skip-packs) ---")
        results["generate_target_manifests"] = True

    # Step 5: Consistency check
    if pack_output and verify_output:
        ok = check_consistency(verify_output, pack_output)
        results["consistency"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 5/8 consistency check: SKIPPED ---")
        results["consistency"] = True

    # Step 6: Pack integrity (extract + hash verification)
    if not args.skip_packs:
        ok, _ = run(
            [sys.executable, "-m", "unittest", "tests.test_pack_integrity", "-v"],
            "6/8 pack integrity",
        )
        results["pack_integrity"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 6/8 pack integrity: SKIPPED (--skip-packs) ---")
        results["pack_integrity"] = True

    # Step 7: Generate README
    if not args.skip_docs:
        ok, _ = run(
            [sys.executable, "scripts/generate_readme.py",
             "--db", "database.json", "--platforms-dir", "platforms"],
            "7/8 generate readme",
        )
        results["generate_readme"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 7/8 generate readme: SKIPPED (--skip-docs) ---")
        results["generate_readme"] = True

    # Step 8: Generate site pages
    if not args.skip_docs:
        ok, _ = run(
            [sys.executable, "scripts/generate_site.py"],
            "8/8 generate site",
        )
        results["generate_site"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 8/8 generate site: SKIPPED (--skip-docs) ---")
        results["generate_site"] = True

    # Summary
    total_elapsed = time.monotonic() - total_start
    print(f"\n{'=' * 60}")
    for step, ok in results.items():
        print(f"  {step:.<40} {'OK' if ok else 'FAILED'}")
    print(f"  {'total':.<40} {total_elapsed:.1f}s")
    print(f"{'=' * 60}")
    print(f"  Pipeline {'COMPLETE' if all_ok else 'FINISHED WITH ERRORS'}")
    print(f"{'=' * 60}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
