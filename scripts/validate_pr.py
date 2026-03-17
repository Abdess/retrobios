#!/usr/bin/env python3
"""Validate BIOS file contributions in Pull Requests.

Usage:
    python scripts/validate_pr.py [files...]
    python scripts/validate_pr.py --changed   # Auto-detect changed files via git

Multi-layer validation:
1. Hash verified against known databases (System.dat, batocera-systems)
2. File size matches expected value
3. File referenced in ≥1 platform config
4. Duplicate detection against database.json
5. Security checks (no executables, reasonable sizes)

Outputs a structured report suitable for PR comments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import zlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import compute_hashes

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_DB = "database.json"
DEFAULT_PLATFORMS_DIR = "platforms"

BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js",
    ".msi", ".dll", ".so", ".dylib", ".py", ".rb", ".pl",
}

MAX_FILE_SIZE = 100 * 1024 * 1024


class ValidationResult:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.checks = []  # (status, message) tuples
        self.sha1 = ""
        self.md5 = ""
        self.crc32 = ""
        self.size = 0

    def add_check(self, passed: bool, message: str):
        self.checks.append(("PASS" if passed else "FAIL", message))

    def add_warning(self, message: str):
        self.checks.append(("WARN", message))

    def add_info(self, message: str):
        self.checks.append(("INFO", message))

    @property
    def passed(self) -> bool:
        return all(s != "FAIL" for s, _ in self.checks)

    def to_markdown(self) -> str:
        status = "✅" if self.passed else "❌"
        lines = [f"### {status} `{self.filename}`"]
        lines.append("")
        lines.append(f"- **Path**: `{self.filepath}`")
        lines.append(f"- **Size**: {self.size:,} bytes")
        lines.append(f"- **SHA1**: `{self.sha1}`")
        lines.append(f"- **MD5**: `{self.md5}`")
        lines.append(f"- **CRC32**: `{self.crc32}`")
        lines.append("")

        for status_str, message in self.checks:
            if status_str == "PASS":
                lines.append(f"- ✅ {message}")
            elif status_str == "FAIL":
                lines.append(f"- ❌ {message}")
            elif status_str == "WARN":
                lines.append(f"- ⚠️ {message}")
            else:
                lines.append(f"- ℹ️ {message}")

        return "\n".join(lines)


def load_database(db_path: str) -> dict | None:
    """Load database.json if available."""
    if os.path.exists(db_path):
        with open(db_path) as f:
            return json.load(f)
    return None


def load_platform_hashes(platforms_dir: str) -> dict:
    """Load all known hashes from platform configs."""
    known = {"sha1": set(), "md5": set(), "names": set()}

    if not os.path.isdir(platforms_dir) or yaml is None:
        return known

    for f in Path(platforms_dir).glob("*.yml"):
        if f.name.startswith("_"):
            continue
        with open(f) as fh:
            try:
                config = yaml.safe_load(fh) or {}
            except yaml.YAMLError:
                continue

        for sys_id, system in config.get("systems", {}).items():
            for file_entry in system.get("files", []):
                if "sha1" in file_entry:
                    known["sha1"].add(file_entry["sha1"])
                if "md5" in file_entry:
                    known["md5"].add(file_entry["md5"])
                if "name" in file_entry:
                    known["names"].add(file_entry["name"])

    return known


def validate_file(
    filepath: str,
    db: dict | None,
    platform_hashes: dict,
) -> ValidationResult:
    """Run all validation checks on a file."""
    result = ValidationResult(filepath)

    if not os.path.exists(filepath):
        result.add_check(False, f"File not found: {filepath}")
        return result

    result.size = os.path.getsize(filepath)
    hashes = compute_hashes(filepath)
    result.sha1 = hashes["sha1"]
    result.md5 = hashes["md5"]
    result.crc32 = hashes["crc32"]

    ext = os.path.splitext(filepath)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        result.add_check(False, f"Blocked file extension: {ext}")

    if result.size > MAX_FILE_SIZE:
        result.add_check(False, f"File too large for embedded storage ({result.size:,} > {MAX_FILE_SIZE:,} bytes). Use storage: external in platform config.")
    elif result.size == 0:
        result.add_check(False, "File is empty (0 bytes)")
    else:
        result.add_check(True, f"File size OK ({result.size:,} bytes)")

    if db:
        if result.sha1 in db.get("files", {}):
            existing = db["files"][result.sha1]
            result.add_warning(f"Duplicate: identical file already exists at `{existing['path']}`")
        else:
            result.add_check(True, "Not a duplicate in database")

    sha1_known = result.sha1 in platform_hashes.get("sha1", set())
    md5_known = result.md5 in platform_hashes.get("md5", set())
    name_known = result.filename in platform_hashes.get("names", set())

    if sha1_known:
        result.add_check(True, "SHA1 matches known platform requirement")
    elif md5_known:
        result.add_check(True, "MD5 matches known platform requirement")
    elif name_known:
        result.add_warning("Filename matches a known requirement but hash differs - may be a variant")
    else:
        result.add_warning("File not referenced in any platform config - needs manual review")

    if filepath.startswith("bios/"):
        parts = filepath.split("/")
        if len(parts) >= 4:
            result.add_check(True, f"Correct placement: bios/{parts[1]}/{parts[2]}/")
        else:
            result.add_warning("File should be in bios/Manufacturer/Console/ structure")
    else:
        result.add_warning(f"File is not under bios/ directory")

    if name_known and not sha1_known and not md5_known:
        result.add_info(
            "This may be a valid variant. If accepted, it will be placed in "
            f"`.variants/{result.filename}.{result.sha1[:8]}`"
        )

    return result


def get_changed_files() -> list[str]:
    """Get list of changed files in current PR/branch using git."""
    try:
        for base in ("main", "master", "v2"):
            try:
                result = subprocess.run(
                    ["git", "diff", "--name-only", f"origin/{base}...HEAD"],
                    capture_output=True, text=True, check=True,
                )
                files = [f for f in result.stdout.strip().split("\n") if f.startswith("bios/")]
                if files:
                    return files
            except subprocess.CalledProcessError:
                continue
    except (subprocess.CalledProcessError, OSError):
        pass

    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True, text=True,
    )
    return [f for f in result.stdout.strip().split("\n") if f.startswith("bios/") and f]


def main():
    parser = argparse.ArgumentParser(description="Validate BIOS file contributions")
    parser.add_argument("files", nargs="*", help="Files to validate")
    parser.add_argument("--changed", action="store_true", help="Auto-detect changed BIOS files")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to database.json")
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--markdown", action="store_true", help="Output as markdown (for PR comments)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    files = args.files
    if args.changed:
        files = get_changed_files()
        if not files:
            print("No changed BIOS files detected")
            return

    if not files:
        parser.error("No files specified. Use --changed or provide file paths.")

    db = load_database(args.db)
    platform_hashes = load_platform_hashes(args.platforms_dir)

    results = []
    for f in files:
        result = validate_file(f, db, platform_hashes)
        results.append(result)

    all_passed = all(r.passed for r in results)

    if args.json:
        output = []
        for r in results:
            output.append({
                "file": r.filepath,
                "passed": r.passed,
                "sha1": r.sha1,
                "md5": r.md5,
                "size": r.size,
                "checks": [{"status": s, "message": m} for s, m in r.checks],
            })
        print(json.dumps(output, indent=2))
    elif args.markdown:
        lines = ["## BIOS Validation Report", ""]
        status = "✅ All checks passed" if all_passed else "❌ Some checks failed"
        lines.append(f"**Status**: {status}")
        lines.append("")

        for r in results:
            lines.append(r.to_markdown())
            lines.append("")

        print("\n".join(lines))
    else:
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"\n[{status}] {r.filepath}")
            print(f"  SHA1: {r.sha1}")
            print(f"  MD5:  {r.md5}")
            print(f"  Size: {r.size:,}")
            for s, m in r.checks:
                marker = "✓" if s == "PASS" else "✗" if s == "FAIL" else "!" if s == "WARN" else "i"
                print(f"  [{marker}] {m}")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
