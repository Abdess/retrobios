#!/usr/bin/env python3
"""Validate BIOS file contributions in Pull Requests.

Usage:
    python scripts/validate_pr.py [files...]
    python scripts/validate_pr.py --changed   # Auto-detect changed files via git

Multi-layer validation:
1. Hash verified against known databases (System.dat, batocera-systems)
2. File size within limits and within the sizes declared for its name
3. File referenced in ≥1 platform config
4. Duplicate detection against database.json
5. Security checks (no executables, reasonable sizes)

Outputs a structured report suitable for PR comments.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    compute_hashes,
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    parse_md5_list,
)
from hashing import parse_hash_list
from nativemode import digest_algorithm
from validation import frontend_digest_matches, inner_rom_check

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_DB = "database.json"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_EMULATORS_DIR = "emulators"

BLOCKED_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".sh",
    ".ps1",
    ".vbs",
    ".js",
    ".msi",
    ".dll",
    ".so",
    ".dylib",
    ".py",
    ".rb",
    ".pl",
}

MAX_FILE_SIZE = 100 * 1024 * 1024
LARGE_FILE_ISSUE_URL = (
    "https://github.com/Abdess/retrobios/issues/new?template=missing-bios.yml"
)


class ValidationResult:
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.checks = []  # (status, message) tuples
        self.sha1 = ""
        self.md5 = ""
        self.crc32 = ""
        self.size = 0

    def add_check(self, passed: bool, message: str) -> None:
        self.checks.append(("PASS" if passed else "FAIL", message))

    def add_warning(self, message: str) -> None:
        self.checks.append(("WARN", message))

    def add_info(self, message: str) -> None:
        self.checks.append(("INFO", message))

    @property
    def passed(self) -> bool:
        return all(s != "FAIL" for s, _ in self.checks)

    def to_markdown(self) -> str:
        status = "PASS" if self.passed else "FAIL"
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
                lines.append(f"- Pass: {message}")
            elif status_str == "FAIL":
                lines.append(f"- Fail: {message}")
            elif status_str == "WARN":
                lines.append(f"- Warning: {message}")
            else:
                lines.append(f"- Info: {message}")

        return "\n".join(lines)


def _note_sizes(sizes: dict[str, list], names: list[str], entry: dict) -> None:
    """Record the sizes an entry accepts under each of its names.

    An entry that declares no size says nothing about it, so a name is
    judged only by the declarations that do.
    """
    size = entry.get("size")
    accepted = []
    if isinstance(size, list):
        accepted = [(int(v), int(v)) for v in size]
    elif isinstance(size, int) and size > 0:
        accepted = [(size, size)]
    if entry.get("min_size") or entry.get("max_size"):
        accepted.append((int(entry.get("min_size") or 0),
                         int(entry.get("max_size") or 2 ** 63)))
    for name in names if accepted else []:
        sizes.setdefault(name, []).extend(accepted)


def load_platform_hashes(platforms_dir: str, db: dict | None = None) -> dict:
    """Load all known hashes from platform configs.

    With the database, `folders` maps each declared hash to the
    bios/<Manufacturer>/<Console>/ folders the collection files its system
    under, read from the other files of that system it holds.
    """
    known = {"sha1": set(), "md5": set(), "sha256": set(), "crc32": set(),
             "names": set(), "folders": {}, "sizes": {}, "entries": {}}
    systems_of: dict[str, set[str]] = {}
    folders_of: dict[str, dict[str, int]] = {}
    files = (db or {}).get("files", {})
    by_md5 = (db or {}).get("indexes", {}).get("by_md5", {})

    if not os.path.isdir(platforms_dir) or yaml is None:
        return known

    # Read the way verify reads them: inheritance and shared groups resolved,
    # and a Recalbox md5 field split into the revisions it lists. The raw
    # file kept "a,b,c" as one value, so a PR adding the seventh accepted
    # falcon.img was told its hash differs.
    for name in list_registered_platforms(platforms_dir, include_archived=True):
        try:
            config = load_platform_config(name, platforms_dir)
        except (OSError, yaml.YAMLError) as exc:
            print(f"WARNING: {name}: {exc}", file=sys.stderr)
            continue

        mode, rule = config.get("verification_mode"), config.get("hash_rule", "")
        for system_id, system in config.get("systems", {}).items():
            for file_entry in system.get("files", []):
                sha1s = parse_hash_list(file_entry.get("sha1"))
                md5s = parse_md5_list(file_entry.get("md5"))
                sha256s = parse_hash_list(file_entry.get("sha256"))
                known["sha1"].update(sha1s)
                known["md5"].update(md5s)
                known["sha256"].update(sha256s)
                if not (sha1s or md5s or sha256s) and isinstance(file_entry.get("size"), int):
                    # The resolver's reading: a crc32 counts where no stronger
                    # hash is declared, bounded by the declared size.
                    known["crc32"].update(
                        (crc.zfill(8), file_entry["size"])
                        for crc in parse_hash_list(file_entry.get("crc32"))
                    )
                if "name" in file_entry:
                    known["names"].add(file_entry["name"])
                    _note_sizes(known["sizes"], [file_entry["name"]], file_entry)
                    # A frontend that hashes a ZIP's member or its members
                    # together, or that takes any hash at the declared size,
                    # answers by its own rule, read per entry.
                    known["entries"].setdefault(file_entry["name"].lower(), []).append(
                        (file_entry, mode, rule, name)
                    )
                for value in (*sha1s, *md5s):
                    systems_of.setdefault(value, set()).add(system_id)
                _note_folder(folders_of, system_id, files, by_md5, sha1s, md5s)

    known["folders"] = _system_homes(systems_of, folders_of)
    return known


def _note_folder(
    folders_of: dict[str, dict[str, int]], system_id: str, files: dict,
    by_md5: dict, sha1s: list[str], md5s: list[str],
) -> None:
    """Count the bios/<Manufacturer>/<Console>/ folder a held file sits in."""
    held = next((s for s in sha1s if s in files), None) or next(
        (by_md5[m] for m in md5s if m in by_md5), None
    )
    parts = str(files.get(held, {}).get("path", "")).split("/")
    if len(parts) >= 4 and parts[0] == "bios" and not parts[2].startswith("."):
        folder = "/".join(parts[:3]) + "/"
        counts = folders_of.setdefault(system_id, {})
        counts[folder] = counts.get(folder, 0) + 1


def _system_homes(
    systems_of: dict[str, set[str]], folders_of: dict[str, dict[str, int]]
) -> dict[str, set[str]]:
    """Hash value to the folders the collection files its systems under.

    A system whose files sit under several manufacturers (arcade sets,
    computers sharing ROM chips) names no single home: only a system filed
    under one manufacturer says where a newcomer belongs.
    """
    homes: dict[str, set[str]] = {}
    for value, systems in systems_of.items():
        folders: set[str] = set()
        for system_id in systems:
            held_in = folders_of.get(system_id, {})
            if len({folder.split("/")[1] for folder in held_in}) == 1:
                folders.update(held_in)
        if folders:
            homes[value] = folders
    return homes


def load_profile_hashes(
    emulators_dir: str, db: dict | None = None
) -> dict[str, dict[str, set[str]]]:
    """Hash value to the emulators whose profile declares it, per algorithm.

    A file only a core reads (a standalone emulator's firmware, a game
    engine's data) is in no platform list: the review called every such
    contribution "not referenced, needs manual review". With the database,
    `folders` maps each declared hash to the folders the collection files
    the entry's system under, as load_platform_hashes does: a contributor
    holding a file only a profile declares was told to pick a
    bios/Manufacturer/Console/ folder alone.
    """
    known: dict[str, dict] = {
        "sha1": {}, "sha256": {}, "md5": {}, "crc32": {}, "sizes": {}, "folders": {},
    }
    systems_of: dict[str, set[str]] = {}
    folders_of: dict[str, dict[str, int]] = {}
    files = (db or {}).get("files", {})
    indexes = (db or {}).get("indexes", {})
    by_md5, by_sha256 = indexes.get("by_md5", {}), indexes.get("by_sha256", {})
    for emulator, profile in load_emulator_profiles(emulators_dir).items():
        declared_systems = profile.get("systems") or []
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict):
                continue
            names = [entry.get("name"), *(entry.get("aliases") or [])]
            _note_sizes(known["sizes"], [n for n in names if isinstance(n, str)], entry)
            # The resolver's reading: comma lists split (mesence's four
            # sha256), and a crc32 counts only where no stronger hash is
            # declared, bounded by the declared size (626 entries name a
            # file by crc32 alone, clk's Electron os.rom among them).
            hashes = {
                algo: parse_hash_list(entry.get(algo)) for algo in ("sha1", "sha256", "md5")
            }
            for algo, values in hashes.items():
                for value in values:
                    known[algo].setdefault(value, set()).add(emulator)
            # The entry's own system, or the profile's when it emulates one.
            system = entry.get("system") or (
                declared_systems[0] if len(declared_systems) == 1 else None
            )
            if isinstance(system, str):
                for value in (v for values in hashes.values() for v in values):
                    systems_of.setdefault(value, set()).add(system)
                sha1s = [*hashes["sha1"], *(
                    by_sha256[v] for v in hashes["sha256"] if v in by_sha256
                )]
                _note_folder(folders_of, system, files, by_md5, sha1s, hashes["md5"])
            if not any(entry.get(algo) for algo in ("sha1", "sha256", "md5")):
                size = entry.get("size")
                sizes = [int(v) for v in size] if isinstance(size, list) else (
                    [int(size)] if size else [None]
                )
                for value in parse_hash_list(entry.get("crc32")):
                    for accepted in sizes:
                        key = (value.zfill(8), accepted)
                        known["crc32"].setdefault(key, set()).add(emulator)
    known["folders"] = _system_homes(systems_of, folders_of)
    return known


def validate_file(
    filepath: str,
    db: dict | None,
    platform_hashes: dict,
    profile_hashes: dict | None = None,
) -> ValidationResult:
    """Run all validation checks on a file."""
    result = ValidationResult(filepath)

    # Whoever opened the pull request chose this path, so its shape is
    # settled before anything is read. A symlink to an endless device would
    # otherwise be hashed until the job timed out, and a symlink out of the
    # checkout would be reported as though its target had been contributed.
    if os.path.islink(filepath):
        result.add_check(False, "Symlinks are not allowed")
        return result

    if not os.path.exists(filepath):
        result.add_check(False, f"File not found: {filepath}")
        return result

    if not os.path.isfile(filepath):
        result.add_check(False, "Not a regular file")
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
        # GitHub refuses a pushed file over 100 MiB, so a pull request cannot
        # carry it. Only a maintainer can add an asset to the release.
        result.add_check(
            False,
            f"File too large for git ({result.size:,} > {MAX_FILE_SIZE:,} bytes). "
            "Leave it out of the pull request and open an issue "
            f"({LARGE_FILE_ISSUE_URL}) with the hashes above and where the file "
            "can be obtained: a maintainer adds it to the `large-files` release.",
        )
    elif result.size == 0:
        result.add_check(False, "File is empty (0 bytes)")
    else:
        result.add_check(True, f"File size within limits ({result.size:,} bytes)")

    # Paths are compared as the database writes them, relative to the
    # checkout: an absolute path to the file itself read as its duplicate.
    relative = filepath
    if os.path.isabs(filepath):
        candidate = os.path.relpath(filepath, os.getcwd())
        if not candidate.startswith(".."):
            relative = candidate

    if db:
        if result.sha1 in db.get("files", {}):
            existing = db["files"][result.sha1]
            held_at = {
                os.path.normpath(p)
                for p in [existing.get("path"), *(existing.get("paths") or [])] if p
            }
            if os.path.normpath(relative) in held_at:
                # The file the database was built from, not a copy of it: a
                # PR that regenerated database.json was told each new file
                # duplicated itself.
                result.add_check(True, "Already in the database at this path")
            else:
                result.add_warning(
                    f"Duplicate: identical file already exists at `{existing['path']}`"
                )
        else:
            result.add_check(True, "Not a duplicate in database")

    sha1_known = result.sha1 in platform_hashes.get("sha1", set())
    md5_known = result.md5 in platform_hashes.get("md5", set())
    other_known = (
        hashes.get("sha256", "") in platform_hashes.get("sha256", set())
        or (result.crc32, result.size) in platform_hashes.get("crc32", set())
    )
    accepted_by = (
        set() if sha1_known or md5_known or other_known
        else _platforms_accepting(filepath, result.filename, platform_hashes)
    )
    name_known = result.filename in platform_hashes.get("names", set())

    profile_hashes = profile_hashes or {}
    by_profile = (
        profile_hashes.get("sha1", {}).get(result.sha1)
        or profile_hashes.get("sha256", {}).get(hashes.get("sha256", ""))
        or profile_hashes.get("md5", {}).get(result.md5)
        or profile_hashes.get("crc32", {}).get((result.crc32, result.size))
        or profile_hashes.get("crc32", {}).get((result.crc32, None))
    )

    if sha1_known:
        result.add_check(True, "SHA1 matches known platform requirement")
    elif md5_known:
        result.add_check(True, "MD5 matches known platform requirement")
    elif other_known:
        result.add_check(True, "Hash matches known platform requirement")
    elif accepted_by:
        result.add_check(
            True, "Accepted by the platform's own check: " + ", ".join(sorted(accepted_by))
        )
    elif by_profile:
        names = sorted(by_profile)
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        result.add_check(True, f"Hash matches a file the emulator profile declares: {shown}")
    elif name_known:
        result.add_warning(
            "Filename matches a known requirement but hash differs - may be a variant"
        )
    else:
        result.add_warning(
            "File not referenced in any platform config - needs manual review"
        )

    normalized = os.path.normpath(relative)
    # A platform's declaration first, then a profile's: most files the gaps
    # page lists are declared by a profile alone.
    expected = next(
        (
            table["folders"][value]
            for table in (platform_hashes, profile_hashes)
            for value in (result.sha1, result.md5, hashes.get("sha256", ""))
            if value in table.get("folders", {})
        ),
        set(),
    )
    expected_folders = sorted(expected)
    if normalized.startswith("bios" + os.sep):
        parts = normalized.split(os.sep)
        here = f"bios/{parts[1]}/{parts[2]}/" if len(parts) >= 4 else ""
        makers = {folder.split("/")[1] for folder in expected}
        if expected and (len(parts) < 4 or parts[1] not in makers):
            # Depth alone passed a PS1 BIOS filed under bios/Nintendo/Game Boy/.
            result.add_warning(
                "Placed under " + (here or "the bios/ root") + ", while the other files of "
                "its system are in " + " or ".join(f"`{f}`" for f in sorted(expected))
            )
        elif len(parts) >= 4:
            result.add_check(True, f"Correct placement: bios/{parts[1]}/{parts[2]}/")
        else:
            result.add_warning("File should be in bios/Manufacturer/Console/ structure")
    elif expected_folders:
        # The contributor asks before forking: say where it goes.
        result.add_warning(
            "File is not under bios/ yet. Its system's files are in "
            + " or ".join(f"`{f}`" for f in expected_folders)
        )
    elif _variant_home(db, result.filename, result.sha1):
        result.add_warning(
            "File is not under bios/ yet. The collection keeps this name in "
            f"`{_variant_home(db, result.filename, result.sha1)}`"
        )
    else:
        result.add_warning(
            "File is not under bios/ yet. Place it in bios/Manufacturer/Console/"
        )

    declared = [
        *platform_hashes.get("sizes", {}).get(result.filename, []),
        *profile_hashes.get("sizes", {}).get(result.filename, []),
    ]
    size_fits = not declared or any(lo <= result.size <= hi for lo, hi in declared)
    if not size_fits:
        expected = sorted({lo if lo == hi else f"{lo:,} to {hi:,}" for lo, hi in declared},
                          key=str)
        shown = ", ".join(f"{v:,}" if isinstance(v, int) else v for v in expected)
        result.add_warning(
            f"Every declaration of {result.filename} expects {shown} bytes, "
            f"this file has {result.size:,}: truncated or another file"
        )

    if (name_known and not (sha1_known or md5_known or other_known or accepted_by)
            and not by_profile and size_fits):
        home = _variant_home(db, result.filename)
        result.add_info(
            "This may be a valid variant. If accepted, it will be placed in "
            f"`{home}.variants/{result.filename}.{result.sha1[:8]}`"
        )

    return result


def _platforms_accepting(filepath: str, filename: str, platform_hashes: dict) -> set[str]:
    """Platforms whose declaration of this name accepts the file by their
    own check, as verify and the pack builder read it.

    Batocera pins a ROM inside the ZIP (zipped_file), Recalbox hashes a
    ZIP's members together, RomM takes any hash at the declared size: the
    container's sha1 or md5 is in none of those lists, and adam_fdc.zip,
    which Batocera accepts, was called an unknown variant.
    """
    accepted: set[str] = set()
    for entry, mode, rule, platform in platform_hashes.get("entries", {}).get(
        filename.lower(), []
    ):
        if platform in accepted:
            continue
        if entry.get("zipped_file"):
            ok = inner_rom_check(entry, filepath) == "ok"
        else:
            algorithm = digest_algorithm(mode)
            ok = bool(algorithm or rule) and frontend_digest_matches(
                entry, filepath, algorithm or "", rule
            )
        if ok:
            accepted.add(platform)
    return accepted


def _variant_home(db: dict | None, name: str, held: str = "") -> str:
    """The folder the collection keeps a name in, for its variants beside it.

    The folder of an identical copy comes first: adam_fdc.zip, held in
    bios/Coleco/Adam/, was sent to bios/Arcade/MAME/, the first folder
    the name index gave.
    """
    files = (db or {}).get("files", {})
    by_name = (db or {}).get("indexes", {}).get("by_name", {}).get(name, [])
    for sha1 in ([held] if held in files else []) + list(by_name):
        path = str(files.get(sha1, {}).get("path", ""))
        folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
        if folder and "/.variants" not in "/" + folder:
            return folder
    return ""


def _git_lines(*args: str) -> list[str] | None:
    """Output lines of a git command, or None when git refuses it."""
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


PROJECT_URLS = (
    "https://github.com/Abdess/retrobios",
    "https://github.com/Abdess/retroarch_system",
)


def _repo_key(url: str) -> str:
    """owner/name of a clone URL, whatever its scheme."""
    path = url.strip().rstrip("/").removesuffix(".git")
    return "/".join(re.split(r"[/:]", path)[-2:]).casefold()


def _project_main_line() -> str | None:
    """The project's main line, fetched when no remote of this clone names it.

    A fork's clone has origin alone. Once the commit is pushed to the fork's
    main, origin/main is HEAD and the diff against it was empty, so --changed
    found nothing and exited 0. None leaves the upstream/ and origin/ lines
    in charge: a remote of that name names the project, or the clone has no
    remote at all and only its uncommitted files can be read.
    """
    remotes = _git_lines("remote") or []
    if not remotes:
        return None
    project = {_repo_key(url) for url in PROJECT_URLS}
    for remote in remotes:
        urls = _git_lines("remote", "get-url", "--all", remote) or []
        if any(_repo_key(url) in project for url in urls):
            return None if remote in ("upstream", "origin") else f"{remote}/main"
    fetched = subprocess.run(
        ["git", "fetch", "--quiet", "--no-tags", PROJECT_URLS[0], "main"],
        capture_output=True, text=True, check=False,
    )
    if fetched.returncode != 0:
        raise RuntimeError(
            f"no remote of this clone is {PROJECT_URLS[0]}, and fetching its "
            f"main failed: {fetched.stderr.strip()}"
        )
    return "FETCH_HEAD"


def get_changed_files() -> list[str]:
    """BIOS files this checkout changes against the project's main line.

    Committed changes are read against the project's main line: the remote
    that names the project (upstream/<base> first, then origin/<base>), or
    the project's main fetched when no remote does. Uncommitted and
    untracked files count too,
    since CONTRIBUTING has the file copied into bios/ before any commit.
    A git that fails outright is an error, never "nothing changed".
    """
    changed: list[str] = []
    compared = False
    project_base = _project_main_line()
    remotes = [[project_base]] if project_base else [
        [f"{remote}/{base}" for base in ("main", "master", "v2")]
        for remote in ("upstream", "origin")
    ]
    for candidates in remotes:
        for line in candidates:
            committed = _git_lines("diff", "--name-only", f"{line}...HEAD")
            if committed is None:
                continue
            compared = True
            changed.extend(committed)
            break
        if compared and changed:
            break
    staged = _git_lines("diff", "--cached", "--name-only")
    local = _git_lines("diff", "--name-only")
    untracked = _git_lines("ls-files", "--others", "--exclude-standard", "--", "bios")
    if staged is None and local is None and untracked is None:
        raise RuntimeError("git cannot read this checkout")
    for found in (staged, local, untracked):
        changed.extend(found or [])
    if not compared:
        print(
            "no upstream/ or origin/ main line to compare against, reading the "
            "staged, modified and untracked files only",
            file=sys.stderr,
        )
    seen: set[str] = set()
    return [
        f for f in changed
        if f.startswith("bios/") and not (f in seen or seen.add(f)) and os.path.isfile(f)
    ]


def _files_to_validate(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> list:
    """The files named on the command line, or the changed ones."""
    if args.changed and args.files:
        # Named files were dropped for the git diff, and the run reported
        # "No changed BIOS files detected" about files it never looked at.
        parser.error("--changed reads the git diff: name files or pass --changed, not both")
    if not args.changed:
        if not args.files:
            parser.error("No files specified. Use --changed or provide file paths.")
        return args.files
    try:
        files = get_changed_files()
    except (RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    if not files and not args.json:
        print("No changed BIOS files detected")
    return files


def _load_database_if_any(path: str) -> dict | None:
    """The database, optional only where the default is meant.

    A mistyped --db read as "no database" and every file passed its
    duplicate and placement checks unchecked. A damaged one did the same
    after a warning.
    """
    if path == DEFAULT_DB and not os.path.exists(path):
        return None
    return load_database(path)


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Validate BIOS file contributions")
    parser.add_argument("files", nargs="*", help="Files to validate")
    parser.add_argument(
        "--changed", action="store_true", help="Auto-detect changed BIOS files"
    )
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to database.json")
    parser.add_argument(
        "--platforms-dir", default=DEFAULT_PLATFORMS_DIR,
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default=DEFAULT_EMULATORS_DIR,
        help="emulator profile directory (default: %(default)s)",
    )
    # One output format: --json beside --markdown printed JSON and dropped
    # the markdown without a word.
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--markdown", action="store_true", help="Output as markdown (for PR comments)"
    )
    output.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    # The database, platforms and profiles are read from the repository
    # root. Run from elsewhere, every file read as referenced by no platform
    # and placed outside bios/. The files named are read from where they
    # were typed.
    from verify import REPO_ROOT, work_from_repo_root

    if os.path.realpath(os.getcwd()) != os.path.realpath(REPO_ROOT):
        args.files = [os.path.abspath(f) for f in args.files]
    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])

    files = _files_to_validate(args, parser)
    if not files:
        if args.json:
            print("[]")
        return

    db = _load_database_if_any(args.db)
    platform_hashes = load_platform_hashes(args.platforms_dir, db)
    profile_hashes = load_profile_hashes(args.emulators_dir, db)

    results = []
    for f in files:
        result = validate_file(f, db, platform_hashes, profile_hashes)
        results.append(result)

    all_passed = all(r.passed for r in results)

    if args.json:
        output = []
        for r in results:
            output.append(
                {
                    "file": r.filepath,
                    "passed": r.passed,
                    "sha1": r.sha1,
                    "md5": r.md5,
                    "size": r.size,
                    "checks": [{"status": s, "message": m} for s, m in r.checks],
                }
            )
        print(json.dumps(output, indent=2))
    elif args.markdown:
        lines = ["## BIOS Validation Report", ""]
        status = "all checks passed" if all_passed else "some checks failed"
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
                marker = (
                    "ok"
                    if s == "PASS"
                    else "fail"
                    if s == "FAIL"
                    else "warn"
                    if s == "WARN"
                    else "info"
                )
                print(f"  [{marker}] {m}")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
