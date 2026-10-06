#!/usr/bin/env python3
"""Compare the large-files release with the files the collection keeps out of git.

Every gitignored file under bios/ is served to the installer as an asset of
the large-files release, and install.py refuses a download whose
Content-Length differs from the manifest size. The manifest size is that of
the local copy, so an asset uploaded before the local file was rebuilt fails
every install of it until it is uploaded again.

Usage:
    python scripts/check_release_assets.py
    python scripts/check_release_assets.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable

sys.path.insert(0, os.path.dirname(__file__))
from common import composition_tier, load_database
from largefiles import (
    LARGE_FILES_RELEASE,
    LARGE_FILES_REPO,
    asset_names,
    registered_paths,
)

Finding = tuple[str, str, int, int | None]


def expected_assets(db: dict, gitignore_text: str) -> dict[str, int]:
    """Map each gitignored database path to the size the manifests carry."""
    ignored = set(registered_paths(gitignore_text))
    return {
        entry["path"]: entry["size"]
        for entry in db.get("files", {}).values()
        if entry.get("path") in ignored
    }


def _spellings(name: str) -> list[str]:
    """Names the release may publish an asset under.

    GitHub rewrites spaces to dots in asset names, so a file whose name
    carries spaces is published under the dotted form.
    """
    return [name, name.replace(" ", ".")] if " " in name else [name]


def compare(
    expected: dict[str, int],
    assets: dict[str, int],
    notes_current: bool = True,
    registered: Iterable[str] | None = None,
) -> list[Finding]:
    """Files the release lacks or serves at another size, sorted by kind.

    *registered* is every path .gitignore lists; an asset name depends on
    which other paths share its basename, so it defaults to *expected* only
    when the caller has nothing wider. A release description that no longer
    matches what render_notes() would write is a finding of its own: the
    page is what a reader checks a download against.
    """
    findings: list[Finding] = []
    if not notes_current:
        findings.append(("notes", "release description", 0, None))
    names = asset_names([*(registered or ()), *expected])
    for path, size in sorted(expected.items()):
        published = next(
            (assets[name] for name in _spellings(names[path]) if name in assets),
            None,
        )
        if published is None:
            findings.append(("missing", path, size, None))
        elif published != size:
            findings.append(("size", path, size, published))
    return sorted(findings)


ASSET_URL = f"https://github.com/{LARGE_FILES_REPO}/releases/download/{LARGE_FILES_RELEASE}/"
NOT_INDEXED = "Not indexed"
SECTIONS = (
    "Console firmware",
    "Arcade",
    "Computer",
    "Game engine data",
    "Virtual machine firmware",
    "Other",
    NOT_INDEXED,
)
_ROW = re.compile(
    r"^\| \[(?P<name>[^\]]+)\]\([^)]*\) \| (?P<desc>[^|]*?) \| [^|]* \|"
    r"(?: `(?P<sha1>[0-9a-f]{40})` \|)?$",
    re.M,
)
_HEADING = re.compile(r"^## (.+)$", re.M)


def parse_notes(body: str) -> dict[str, tuple[str, str, str]]:
    """Name -> (section, description, sha1) for every row of a release page."""
    rows: dict[str, tuple[str, str, str]] = {}
    section = ""
    for line in body.splitlines():
        heading = _HEADING.match(line)
        if heading:
            section = heading.group(1).strip()
            continue
        row = _ROW.match(line)
        if row:
            rows[row.group("name")] = (
                section, row.group("desc").strip(), row.group("sha1") or ""
            )
    return rows


def _section_for(path: str) -> str:
    parts = path.split("/")
    top = parts[1] if len(parts) > 1 else ""
    if top in ("Nintendo", "Sony", "Sega", "Microsoft", "NEC", "SNK"):
        return "Console firmware"
    if top == "Arcade" or "/samples/" in path:
        return "Arcade"
    if top == "QEMU":
        return "Virtual machine firmware"
    if composition_tier(path) == "game_data":
        return "Game engine data"
    if top in ("Apple", "Commodore", "Atari", "Sinclair", "Amstrad"):
        return "Computer"
    return "Other"


def _mib(size: int) -> str:
    return f"{round(size / 1048576)} MB"


def render_notes(
    db: dict,
    gitignore_text: str,
    assets: dict[str, int],
    previous: str,
    descriptions: dict[str, str],
    bundles: dict[str, str],
    cache_sha1: dict[str, str],
) -> str:
    """The release page, from what the release actually serves.

    Every asset gets one row. A file the database indexes carries its
    database SHA1; a data-directory bundle carries the hash of its cached
    copy when one exists; anything else is listed apart with its size only,
    so the page never vouches for bytes nobody indexed. Descriptions and
    sections already written by hand are kept by name.
    """
    known = parse_notes(previous)
    names = asset_names(registered_paths(gitignore_text))
    indexed: dict[str, tuple[str, str]] = {}
    for sha1, entry in db.get("files", {}).items():
        path = entry.get("path", "")
        if path in names:
            for candidate in _spellings(names[path]):
                indexed[candidate] = (sha1, path)

    rows: dict[str, list[tuple[int, str]]] = {section: [] for section in SECTIONS}
    for name, size in assets.items():
        section, description, previous_sha1 = known.get(name, ("", "", ""))
        if name in indexed:
            sha1, path = indexed[name]
            section = section if section in SECTIONS[:-1] else _section_for(path)
            stem = name.split(".")[0] + "." + name.split(".")[1] if name.count(".") > 1 else name
            description = description or descriptions.get(name) or descriptions.get(stem) or path
        elif name in bundles:
            sha1 = cache_sha1.get(name, previous_sha1)
            section = section if section in SECTIONS[:-1] else "Game engine data"
            description = description or bundles[name]
        else:
            sha1 = ""
            section = NOT_INDEXED
            description = description or name
        link = f"[{name}]({ASSET_URL}{name})"
        if section == NOT_INDEXED:
            line = f"| {link} | {description} | {_mib(size)} |"
        else:
            line = f"| {link} | {description} | {_mib(size)} | `{sha1}` |"
        rows[section].append((-size, line))

    out = [
        "Files too large for the git repository (GitHub 100MB limit), plus game engine data packs.",
        "Downloaded automatically by `generate_pack.py` when not present locally.",
        "Manual: `gh release download large-files`",
    ]
    for section in SECTIONS:
        if not rows[section]:
            continue
        out += ["", f"## {section}", ""]
        if section == NOT_INDEXED:
            out += [
                "Assets the collection does not index: no database entry names them, "
                "so no hash is vouched for here.",
                "",
                "| File | Description | Size |",
                "|------|-------------|-----:|",
            ]
        else:
            out += ["| File | Description | Size | SHA1 |", "|------|-------------|-----:|------|"]
        out += [line for _, line in sorted(rows[section])]
    total = sum(assets.values())
    out += ["", f"{len(assets)} files, {total / 1073741824:.1f} GB total. Verify a download with `sha1sum <file>`.", ""]
    return "\n".join(out)


def profile_descriptions(emulators_dir: str = "emulators") -> dict[str, str]:
    """Name -> description, from the first profile that declares the file."""
    from common import load_emulator_profiles

    found: dict[str, str] = {}
    for profile in load_emulator_profiles(emulators_dir).values():
        for entry in profile.get("files", []):
            name = str(entry.get("name") or "")
            if name and entry.get("description"):
                found.setdefault(name, str(entry["description"]))
    return found


def registry_bundles(registry_path: str = "platforms/_data_dirs.yml") -> dict[str, str]:
    """Asset name -> description for data directories served from the release."""
    from common import yaml_load

    with open(registry_path, encoding="utf-8") as handle:
        registry = yaml_load(handle) or {}
    bundles: dict[str, str] = {}
    for entry in (registry.get("data_directories") or registry).values():
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("source_url") or "")
        if url.startswith(ASSET_URL):
            bundles[url[len(ASSET_URL):]] = str(entry.get("description") or "")
    return bundles


def cache_hashes(names: set[str], cache_dir: str = ".cache/large") -> dict[str, str]:
    """SHA1 of the cached copy of each named asset that the cache holds."""
    hashes: dict[str, str] = {}
    for name in names:
        path = os.path.join(cache_dir, name)
        if os.path.isfile(path):
            digest = hashlib.sha1()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            hashes[name] = digest.hexdigest()
    return hashes


def fetch_release() -> tuple[dict[str, int], str]:
    """Name and size of every asset of the large-files release, and its page."""
    result = subprocess.run(
        [
            "gh", "release", "view", LARGE_FILES_RELEASE,
            "-R", LARGE_FILES_REPO, "--json", "assets,body",
        ],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(result.stdout)
    return {a["name"]: a["size"] for a in data["assets"]}, data.get("body", "")


def fetch_assets() -> dict[str, int]:
    """Name and size of every asset of the large-files release."""
    result = subprocess.run(
        [
            "gh", "release", "view", LARGE_FILES_RELEASE,
            "-R", LARGE_FILES_REPO, "--json", "assets",
        ],
        capture_output=True, text=True, check=True,
    )
    return {a["name"]: a["size"] for a in json.loads(result.stdout)["assets"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--db", default="database.json")
    parser.add_argument("--gitignore", default=".gitignore")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--notes", metavar="FILE",
        help="write the release page rendered from the collection to FILE",
    )
    args = parser.parse_args()

    with open(args.gitignore, encoding="utf-8") as handle:
        gitignore_text = handle.read()
    db = load_database(args.db)
    expected = expected_assets(db, gitignore_text)
    try:
        assets, body = fetch_release()
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError) as exc:
        print(f"ERROR: cannot list release assets: {exc}", file=sys.stderr)
        return 2
    bundles = registry_bundles()
    rendered = render_notes(
        db, gitignore_text, assets, body, profile_descriptions(), bundles,
        cache_hashes(set(bundles)),
    )
    if args.notes:
        with open(args.notes, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    findings = compare(
        expected,
        assets,
        notes_current=rendered.strip() == body.strip(),
        registered=registered_paths(gitignore_text),
    )

    if args.json:
        print(json.dumps(
            [
                {"kind": kind, "path": path, "expected": size, "published": published}
                for kind, path, size, published in findings
            ],
            indent=2,
        ))
    else:
        print(f"{len(expected)} gitignored files, {len(assets)} release assets")
        for kind, path, size, published in findings:
            if kind == "missing":
                print(f"  MISSING  {path} ({size} bytes)")
            elif kind == "size":
                print(f"  SIZE     {path}: local {size} != release {published}")
            else:
                print("  NOTES    release description differs from the rendered page"
                      " (--notes FILE, then gh release edit large-files --notes-file FILE)")
        if not findings:
            print("  release assets and description match the collection")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
