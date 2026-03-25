#!/usr/bin/env python3
"""Run the full retrobios pipeline.

Steps:
  1. generate_db.py --force     (rebuild database.json from bios/)
  2. refresh_data_dirs.py       (update Dolphin Sys, PPSSPP, etc.)
  3. verify.py --all            (check all platforms)
  4. generate_pack.py --all     (build ZIP packs)
  5. consistency check          (verify counts == pack counts)
  6. generate_readme.py         (rebuild README.md + CONTRIBUTING.md)
  7. generate_site.py           (rebuild MkDocs pages)

Usage:
    python scripts/pipeline.py                    # active platforms
    python scripts/pipeline.py --include-archived # all platforms
    python scripts/pipeline.py --skip-packs       # steps 1-3 only
    python scripts/pipeline.py --skip-docs        # skip steps 6-7
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

    print("\n--- 5/7 consistency check ---")
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
            if v_ok == p_ok and v_total == p_total:
                print(f"  {v_label}: verify {v_ok}/{v_total} == pack {p_ok}/{p_total} OK")
            else:
                print(f"  {v_label}: MISMATCH verify {v_ok}/{v_total} != pack {p_ok}/{p_total}")
                all_ok = False
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
    args = parser.parse_args()

    results = {}
    all_ok = True
    total_start = time.monotonic()

    # Step 1: Generate database
    ok, out = run(
        [sys.executable, "scripts/generate_db.py", "--force",
         "--bios-dir", "bios", "--output", "database.json"],
        "1/7 generate database",
    )
    results["generate_db"] = ok
    if not ok:
        print("\nDatabase generation failed, aborting.")
        sys.exit(1)

    # Step 2: Refresh data directories
    if not args.offline:
        ok, out = run(
            [sys.executable, "scripts/refresh_data_dirs.py"],
            "2/7 refresh data directories",
        )
        results["refresh_data"] = ok
    else:
        print("\n--- 2/7 refresh data directories: SKIPPED (--offline) ---")
        results["refresh_data"] = True

    # Step 3: Verify
    verify_cmd = [sys.executable, "scripts/verify.py", "--all"]
    if args.include_archived:
        verify_cmd.append("--include-archived")
    ok, verify_output = run(verify_cmd, "3/7 verify all platforms")
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
        ok, pack_output = run(pack_cmd, "4/7 generate packs")
        results["generate_packs"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 4/7 generate packs: SKIPPED (--skip-packs) ---")
        results["generate_packs"] = True

    # Step 5: Consistency check
    if pack_output and verify_output:
        ok = check_consistency(verify_output, pack_output)
        results["consistency"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 5/7 consistency check: SKIPPED ---")
        results["consistency"] = True

    # Step 6: Generate README
    if not args.skip_docs:
        ok, _ = run(
            [sys.executable, "scripts/generate_readme.py",
             "--db", "database.json", "--platforms-dir", "platforms"],
            "6/7 generate readme",
        )
        results["generate_readme"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 6/7 generate readme: SKIPPED (--skip-docs) ---")
        results["generate_readme"] = True

    # Step 7: Generate site pages
    if not args.skip_docs:
        ok, _ = run(
            [sys.executable, "scripts/generate_site.py"],
            "7/7 generate site",
        )
        results["generate_site"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 7/7 generate site: SKIPPED (--skip-docs) ---")
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
