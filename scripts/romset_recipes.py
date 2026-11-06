#!/usr/bin/env python3
"""Identify and reconstruct arcade romset archives from their recipes.

A profile's ``contents:`` block is a recipe: the member names and CRC32s one
emulator version expects inside an archive. TorrentZip makes archive bytes a
function of that recipe alone, so a recipe plus the ROM bytes reproduces the
archive exactly.

Two questions follow, and this module answers both:

``--identify``
    Which version does an archive the collection holds correspond to? The
    recipe that rebuilds it byte for byte names it.

``--missing``
    A platform pins a container MD5 the collection does not have. If some
    recipe plus ROMs already present reproduces that MD5, the archive is
    constructible rather than absent.

Reconstruction is only possible when the pinned archive is itself TorrentZip.
An archive whose bytes carry metadata unrelated to its contents cannot be
derived from ROMs by anyone, and is reported as such rather than guessed at.

Every archive the collection holds also has a recipe of its own in
``recipes/archives.json`` (scripts/archive_build.py):

``--capture``
    Write a record for every archive in database.json: members in order with
    size, crc32 and sha1, container sha1, md5 and size, and whether the
    TorrentZip build reproduces the bytes (``exact``) or only the members
    (``canonical``). Archives already recorded under the same sha1 are not
    read again.

``--build NAME --output-dir DIR``
    Build an archive from the members the collection holds, loose or inside
    another archive, and verify it before moving it into place.

``--build-all --output-dir DIR``
    The same for every recorded archive, with one line per archive: exact,
    canonical, or impossible with the member nothing holds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    require_directory,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    list_registered_platforms,
)
from torrentzip import build_torrentzip, is_torrentzip

ARCHIVES_FILE = Path(__file__).resolve().parent.parent / "recipes" / "archives.json"

Recipe = list[tuple[str, str]]


def load_dat_recipes(path: str | Path) -> dict[str, dict[str, Recipe]]:
    """Recipes imported from MAME or FBNeo DATs.

    A DAT documents every set of one emulator version, where profiles only
    document the few hundred the collection curates by hand. Labels are
    prefixed so an identification says which DAT decided it.
    """
    target = Path(path)
    if target.is_dir():
        merged: dict[str, dict[str, Recipe]] = {}
        for snapshot_file in sorted(target.glob("*.json")):
            merged = merge_recipes(merged, load_dat_recipes(snapshot_file))
        return merged
    snapshot_path = target
    if not snapshot_path.is_file():
        return {}
    with snapshot_path.open(encoding="utf-8") as handle:
        snapshot = json.load(handle)
    source = snapshot.get("source", "dat")
    # A recipe shared by several versions is stored once under the earliest.
    # The label therefore reads "unchanged since", not "is this version".
    recipes: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for entry in snapshot.get("entries", []):
        archive = entry.get("name", "")
        members = entry.get("members", []) or []
        recipe = [
            (str(member["name"]), str(member.get("crc32") or "").lower())
            for member in members
            if member.get("name") is not None
        ]
        if not archive or not recipe or not all(crc for _name, crc in recipe):
            continue
        label = f"{source}:{entry.get('dat', 'unnamed')}"
        recipes[archive][label] = recipe
    return dict(recipes)


def merge_recipes(*sources: dict[str, dict[str, Recipe]]) -> dict[str, dict[str, Recipe]]:
    """Combine recipe sets, keeping every label distinct."""
    merged: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for source in sources:
        for archive, per_label in source.items():
            merged[archive].update(per_label)
    return dict(merged)


def collect_recipes(profiles: dict) -> dict[str, dict[str, Recipe]]:
    """Map each archive name to one recipe per profile that documents it.

    A recipe is only usable when every member carries a CRC32: the pool is
    addressed by content, so a member without one cannot be located.
    """
    recipes: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for profile_name, profile in sorted(profiles.items()):
        for entry in profile.get("files", []) or []:
            contents = entry.get("contents")
            archive = entry.get("name", "")
            if not contents or not archive:
                continue
            recipe = [
                (str(member["name"]), str(member.get("crc32") or "").lower())
                for member in contents
                if member.get("name") is not None
            ]
            if recipe and all(crc for _name, crc in recipe):
                recipes[archive][profile_name] = recipe
    return dict(recipes)


class AtomPool:
    """ROM bytes in the collection, addressed by CRC32.

    Members are located once and read on demand: arcade sample sets reach
    hundreds of megabytes and a whole-pool preload buys nothing.
    """

    def __init__(
        self, bios_dir: Path, digest_cache: Path | None = None, db: dict | None = None
    ) -> None:
        # crc32 -> (archive, member), or (file, None) for a loose ROM.
        self._index: dict[str, tuple[Path, str | None]] = {}
        # (md5, size) of each build, kept across runs: TorrentZip bytes are a
        # function of the members alone, so a recipe hashed once is known
        # until the writer changes. Rebuilding the 1 221 archives took 70 s
        # of every pipeline run, 63 s of it in zlib.
        self._digest_cache = digest_cache
        self._digests: dict[str, list] = _read_digests(digest_cache)
        self._digests_changed = False
        # A recipe is built once: identification and reconstruction ask for the
        # same archives, and every build re-reads and re-deflates its ROMs.
        self._built: dict[tuple[tuple[str, str], ...], bytes | None] = {}
        self.unreadable: list[str] = []
        for archive in sorted(bios_dir.rglob("*.zip")):
            try:
                with zipfile.ZipFile(archive) as handle:
                    for info in handle.infolist():
                        if not info.is_dir():
                            self._index.setdefault(
                                f"{info.CRC:08x}", (archive, info.filename)
                            )
            except (OSError, zipfile.BadZipFile) as exc:
                self.unreadable.append(f"{archive}: {exc}")
        # Loose ROMs, by the crc32 the database already computed: nmk004.zip
        # needs nmk004.bin, which the collection holds only as a file.
        root = bios_dir.resolve()
        for entry in ((db or {}).get("files") or {}).values():
            crc, path = str(entry.get("crc32") or "").lower(), entry.get("path", "")
            if not crc or not path or path.lower().endswith(".zip"):
                continue
            loose = Path(path)
            if root in loose.resolve().parents and loose.is_file():
                self._index.setdefault(crc, (loose, None))

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, crc32: str) -> bool:
        return crc32.lower() in self._index

    def read(self, crc32: str) -> bytes:
        archive, member = self._index[crc32.lower()]
        if member is None:
            return archive.read_bytes()
        with zipfile.ZipFile(archive) as handle:
            return handle.read(member)

    def digest(self, recipe: Recipe) -> tuple[str, int] | None:
        """(md5, size) of the recipe's TorrentZip build, None if incomplete."""
        if not all(crc in self for _name, crc in recipe):
            return None
        key = _recipe_key(recipe)
        known = self._digests.get(key)
        if known is None:
            blob = self.build(recipe)
            if blob is None:
                return None
            known = self._digests[key] = [hashlib.md5(blob).hexdigest(), len(blob)]
            self._digests_changed = True
        return known[0], known[1]

    def save_digests(self) -> None:
        """Write the digest cache back, when this run learned anything."""
        if self._digest_cache is None or not self._digests_changed:
            return
        from artifacts import write_text_atomic  # noqa: PLC0415

        self._digest_cache.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(
            str(self._digest_cache), json.dumps(self._digests, sort_keys=True) + "\n"
        )

    def build(self, recipe: Recipe) -> bytes | None:
        """Return the TorrentZip bytes for *recipe*, or None if incomplete."""
        key = tuple(recipe)
        if key not in self._built:
            if all(crc in self for _name, crc in recipe):
                self._built[key] = build_torrentzip(
                    [(name, self.read(crc)) for name, crc in recipe]
                )
            else:
                self._built[key] = None
        return self._built[key]


DIGEST_CACHE = Path(__file__).resolve().parent.parent / ".cache" / "romset_digests.json"
# The writer's own source is part of every key: a change to how TorrentZip
# bytes are laid out invalidates every digest it produced.
_WRITER = hashlib.sha256(
    (Path(__file__).resolve().parent / "torrentzip.py").read_bytes()
).hexdigest()[:16]


def _recipe_key(recipe: Recipe) -> str:
    members = json.dumps([[name, crc.lower()] for name, crc in recipe])
    return hashlib.sha256(f"{_WRITER}:{members}".encode()).hexdigest()


def _read_digests(path: Path | None) -> dict[str, list]:
    if path is None:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        print(f"  digest cache {path} unreadable, rebuilding: {exc}", file=sys.stderr)
        return {}
    return data if isinstance(data, dict) else {}


def identify_archive(
    path: Path, recipes: dict[str, Recipe], pool: AtomPool
) -> str | None:
    """Return the recipe label that reproduces *path* byte for byte.

    Equal bytes need equal (name, crc32) members, which the archive's
    central directory gives without inflating anything: building every
    recipe at DEFLATE level 9 first took 94 s and 1 GB at pipeline step 1c.
    """
    held = _member_list(path)
    if held is None:
        return None
    original = path.read_bytes()
    md5, size = hashlib.md5(original).hexdigest(), len(original)
    for label, recipe in sorted(recipes.items()):
        if sorted((name, crc.lower()) for name, crc in recipe) != held:
            continue
        if pool.digest(recipe) == (md5, size):
            return label
    return None


def _member_list(path: Path) -> list[tuple[str, str]] | None:
    """Sorted (name, crc32) of an archive's members, from its directory."""
    try:
        with zipfile.ZipFile(path) as archive:
            return sorted(
                (info.filename, format(info.CRC, "08x"))
                for info in archive.infolist() if not info.is_dir()
            )
    except (zipfile.BadZipFile, OSError) as exc:
        print(f"  UNREADABLE: {path}: {exc}", file=sys.stderr)
        return None


def reconstruct(
    target_md5: str, recipes: dict[str, Recipe], pool: AtomPool
) -> tuple[str, bytes] | None:
    """Return the (label, bytes) whose TorrentZip build matches *target_md5*."""
    target = target_md5.lower()
    for label, recipe in sorted(recipes.items()):
        known = pool.digest(recipe)
        if known is not None and known[0] == target:
            blob = pool.build(recipe)
            if blob is not None and hashlib.md5(blob).hexdigest() == target:
                return label, blob
    return None


def platform_targets(platforms_dir: str) -> dict[str, set[str]]:
    """Container MD5s the platforms pin, per archive name.

    ``zipped_file`` entries pin an inner ROM instead of the container, so
    their MD5 is not an archive hash and is skipped. So is a Recalbox md5,
    the composite of the members (``zip_digest: composite``, Bios.cpp:64-68):
    no container build can ever give it.
    """
    targets: dict[str, set[str]] = defaultdict(set)
    for name in list_registered_platforms(platforms_dir):
        config = load_platform_config(name, platforms_dir)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []) or []:
                archive = entry.get("name", "")
                if (
                    not archive.endswith(".zip")
                    or entry.get("zipped_file")
                    or entry.get("zip_digest") == "composite"
                ):
                    continue
                for value in str(entry.get("md5") or "").split(","):
                    value = value.strip().lower()
                    if len(value) == 32:
                        targets[archive].add(value)
    return dict(targets)


def _is_archive(path: Path) -> bool:
    """Whether *path* is a readable ZIP.

    A name index entry can be an alias: ``d2fdc.zip`` names a loose Apple II
    ROM, not an archive. Recipes only describe archives.
    """
    try:
        with zipfile.ZipFile(path):
            return True
    except (OSError, zipfile.BadZipFile):
        return False


def _local_paths(archive: str, db: dict) -> list[Path]:
    matches = db["indexes"]["by_name"].get(archive) or []
    if isinstance(matches, str):
        matches = [matches]
    paths = [Path(db["files"][sha1]["path"]) for sha1 in matches if sha1 in db["files"]]
    return [path for path in paths if path.is_file() and _is_archive(path)]


def identify_report(
    recipes: dict[str, dict[str, Recipe]], pool: AtomPool, db: dict
) -> dict:
    """Label every archive the collection holds with the version it matches."""
    identified: list[dict] = []
    unidentified: list[dict] = []
    for archive, per_profile in sorted(recipes.items()):
        for path in _local_paths(archive, db):
            label = identify_archive(path, per_profile, pool)
            record = {
                "archive": archive,
                "path": str(path),
                "torrentzip": is_torrentzip(path),
            }
            if label:
                record["recipe"] = label
                identified.append(record)
            else:
                record["candidates"] = sorted(per_profile)
                unidentified.append(record)
    return {"identified": identified, "unidentified": unidentified}


def missing_report(
    recipes: dict[str, dict[str, Recipe]],
    pool: AtomPool,
    db: dict,
    platforms_dir: str,
) -> dict:
    """Pinned archives the collection lacks, split by why they are absent."""
    have = set(db["indexes"]["by_md5"])
    constructible: list[dict] = []
    no_recipe: list[dict] = []
    unreproducible: list[dict] = []
    for archive, pinned in sorted(platform_targets(platforms_dir).items()):
        per_profile = recipes.get(archive, {})
        for target in sorted(pinned - have):
            if not per_profile:
                no_recipe.append({"archive": archive, "md5": target})
                continue
            found = reconstruct(target, per_profile, pool)
            if found:
                label, blob = found
                constructible.append(
                    {
                        "archive": archive,
                        "md5": target,
                        "recipe": label,
                        "size": len(blob),
                    }
                )
            else:
                usable = [
                    label
                    for label, recipe in per_profile.items()
                    if all(crc in pool for _name, crc in recipe)
                ]
                unreproducible.append(
                    {
                        "archive": archive,
                        "md5": target,
                        "recipes_tried": sorted(usable),
                        "reason": (
                            "no recipe reproduces this MD5: the pinned archive is "
                            "not TorrentZip or follows a recipe not documented here"
                            if usable
                            else "ROMs for every documented recipe are missing"
                        ),
                    }
                )
    return {
        "constructible": constructible,
        "unreproducible": unreproducible,
        "no_recipe": no_recipe,
    }


def write_reconstructions(
    entries: list[dict],
    recipes: dict[str, dict[str, Recipe]],
    pool: AtomPool,
    bios_dir: Path,
    db: dict,
) -> list[str]:
    """Write each constructible archive beside its set, as a variant."""
    written: list[str] = []
    for entry in entries:
        archive = entry["archive"]
        recipe = recipes[archive][entry["recipe"]]
        blob = pool.build(recipe)
        if blob is None:
            continue
        siblings = _local_paths(archive, db)
        parent = siblings[0].parent if siblings else bios_dir
        destination = parent / ".variants" / f"{archive}.{entry['md5'][:8]}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(blob)
        written.append(str(destination))
    return written


def print_missing(gap: dict) -> None:
    """The pinned archives the collection lacks, each one named."""
    print(
        f"\nPinned archives not held: "
        f"{len(gap['constructible'])} buildable, "
        f"{len(gap['unreproducible'])} not reproducible, "
        f"{len(gap['no_recipe'])} without a recipe"
    )
    for record in gap["constructible"]:
        print(
            f"  BUILDABLE: {record['archive']} md5={record['md5'][:8]} "
            f"via {record['recipe']} ({record['size']} bytes)"
        )
    # The acquisition targets: an archive pinned under several md5s is
    # one line, the platforms' own bundles rather than romsets.
    by_archive: dict[str, list[str]] = defaultdict(list)
    for record in gap["unreproducible"]:
        by_archive[record["archive"]].append(record["md5"][:8])
    for archive, md5s in sorted(by_archive.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"  NOT REPRODUCIBLE: {archive} ({len(md5s)} pinned: {', '.join(sorted(md5s))})")
    for record in gap["no_recipe"]:
        print(f"  NO RECIPE: {record['archive']} md5={record['md5'][:8]}")


def run_capture(args: argparse.Namespace, db: dict) -> int:
    """Write recipes/archives.json for every archive the database lists."""
    import archive_build  # noqa: PLC0415

    try:
        records, failed = archive_build.capture(
            db,
            archive_build.load_ledger(Path(args.archives)),
            archive_build.recipe_index(args.emulators_dir, args.dat_recipes),
            archive_build.container_pins(args.platforms_dir, args.emulators_dir),
        )
    except archive_build.ZlibNgError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for path, reason in sorted(failed.items()):
        print(f"  UNREADABLE: {path}: {reason}", file=sys.stderr)
    changed = archive_build.write_ledger(records, Path(args.archives))
    by_class: dict[str, int] = defaultdict(int)
    for record in records.values():
        by_class[record["rebuild"]] += 1
    agreed = sum(1 for record in records.values() if len(record["sources"]) > 1)
    pinned = sum(1 for record in records.values() if record.get("bytes_pinned"))
    print(
        f"{len(records)} archive recipes: {by_class['exact']} exact, "
        f"{by_class['canonical']} canonical; {agreed} agree with a profile or DAT "
        f"recipe, {pinned} pinned as bytes"
    )
    print(f"{'Wrote' if changed else 'Unchanged'} {args.archives}")
    return 1 if failed else 0


def run_build(args: argparse.Namespace, db: dict) -> int:
    """Build one archive, or all of them, from the members the collection holds."""
    import archive_build  # noqa: PLC0415

    if not args.output_dir:
        print("ERROR: --build and --build-all need --output-dir", file=sys.stderr)
        return 2
    ledger = archive_build.load_ledger(Path(args.archives))
    if args.build_all:
        records = [ledger[path] for path in sorted(ledger)]
    else:
        records = archive_build.select(ledger, args.build)
        if not records:
            print(f"ERROR: no archive recipe named {args.build}", file=sys.stderr)
            return 2
    ng = archive_build.zlib_ng_version()
    if ng:
        print(
            f"  zlib-ng {ng} in use: TorrentZip bytes are stock zlib's output, so no "
            "build is claimed exact here; exact recipes are checked by their members"
        )
    root = Path(args.bios_dir).resolve().parent
    atoms = archive_build.AtomIndex.from_collection(ledger, db, root)
    counts: dict[str, int] = defaultdict(int)
    own: list[tuple[str, int]] = []
    for record in records:
        result = archive_build.build_archive(record, atoms, Path(args.output_dir), root)
        counts[result.status] += 1
        if result.own_members:
            own.append((result.path, result.own_members))
        if result.status == "impossible":
            for member in result.missing:
                print(
                    f"  IMPOSSIBLE: {result.path}: missing {member['name']} "
                    f"({member['sha1']})"
                )
        elif result.status == "failed":
            print(f"  FAILED: {result.path}: {result.detail}")
        else:
            note = f" ({result.detail})" if result.detail else ""
            print(f"  {result.status.upper()}: {result.path}{note}")
            if args.discard:
                Path(result.output).unlink()
    print(
        f"\n{len(records)} archives: {counts['exact']} rebuilt exact, "
        f"{counts['canonical']} canonical, {counts['impossible']} impossible, "
        f"{counts['failed']} failed"
    )
    print(
        f"  {len(own)} of them read {sum(n for _p, n in own)} members from their "
        "own archive, held nowhere else in the collection"
    )
    if counts["failed"]:
        print("ERROR: a build did not match its recipe and was not kept", file=sys.stderr)
        return 1
    return 1 if counts["impossible"] else 0


def _resolve_modes(args: argparse.Namespace) -> None:
    """Which reports run: both by default, and --missing whenever --write.

    The reconstructions --write saves are those of the missing pins: with
    --identify alone beside it, nothing ran them, nothing was written, and
    the run exited 0.
    """
    if args.write:
        args.missing = True
    if not args.identify and not args.missing:
        args.identify = args.missing = True


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=__doc__.replace("``", ""),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--identify", action="store_true", help="label local archives")
    parser.add_argument(
        "--missing", action="store_true", help="attempt pinned archives we lack"
    )
    parser.add_argument(
        "--write", action="store_true",
        help="write reconstructions to .variants/ (implies --missing)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--bios-dir", default="bios",
        help="BIOS collection directory (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--db", default="database.json",
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--dat-recipes",
        default="recipes",
        help="recipe snapshot file, or a directory of them",
    )
    parser.add_argument(
        "--archives", default=str(ARCHIVES_FILE),
        help="archive recipe file (default: recipes/archives.json)",
    )
    parser.add_argument(
        "--capture", action="store_true",
        help="write a recipe for every archive in the database",
    )
    build = parser.add_mutually_exclusive_group()
    build.add_argument("--build", metavar="ARCHIVE", help="build one archive, by path or name")
    build.add_argument("--build-all", action="store_true", help="build every recorded archive")
    parser.add_argument("--output-dir", help="where --build and --build-all write")
    parser.add_argument(
        "--discard", action="store_true",
        help="delete each build once verified: a full proof without the disk space",
    )
    args = parser.parse_args()
    require_directory(args.bios_dir)
    if (args.output_dir or args.discard) and not (args.build or args.build_all):
        parser.error("--output-dir and --discard need --build or --build-all")
    if args.capture and (args.build or args.build_all):
        parser.error("--capture runs alone")

    db = load_database(args.db)
    if args.capture:
        return run_capture(args, db)
    if args.build or args.build_all:
        return run_build(args, db)
    _resolve_modes(args)
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    profile_recipes = collect_recipes(profiles)
    dat_recipes = load_dat_recipes(args.dat_recipes)
    recipes = merge_recipes(profile_recipes, dat_recipes)
    pool = AtomPool(Path(args.bios_dir), DIGEST_CACHE, db)

    result: dict = {
        "recipes": sum(len(v) for v in recipes.values()),
        "profile_recipes": sum(len(v) for v in profile_recipes.values()),
        "dat_recipes": sum(len(v) for v in dat_recipes.values()),
        "archives_with_recipes": len(recipes),
        "atoms": len(pool),
    }
    if pool.unreadable:
        result["unreadable_archives"] = pool.unreadable
    if args.identify:
        result["identify"] = identify_report(recipes, pool, db)
    if args.missing:
        result["missing"] = missing_report(recipes, pool, db, args.platforms_dir)
        if args.write:
            result["written"] = write_reconstructions(
                result["missing"]["constructible"], recipes, pool,
                Path(args.bios_dir), db,
            )

    pool.save_digests()

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    print(
        f"{result['archives_with_recipes']} archives described by "
        f"{result['recipes']} recipes "
        f"({result['profile_recipes']} from profiles, {result['dat_recipes']} from DATs), "
        f"{result['atoms']} ROM atoms available"
    )
    if not result["dat_recipes"]:
        print(
            "  No DAT recipe: import one with "
            "`python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289`"
        )
    for problem in result.get("unreadable_archives", []):
        print(f"  UNREADABLE: {problem}")

    if args.identify:
        ident = result["identify"]
        print(
            f"\nIdentification: {len(ident['identified'])} archives reproduced "
            f"by a recipe, {len(ident['unidentified'])} unidentified"
        )
        print(
            "  The label is the oldest version producing these bytes: a recipe "
            "unchanged since 0.190 is counted there, not at its own version."
        )
        by_recipe: dict[str, int] = defaultdict(int)
        for record in ident["identified"]:
            by_recipe[record["recipe"]] += 1
        for label, count in sorted(by_recipe.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {label}: {count}")
        for record in ident["unidentified"][:10]:
            print(f"  UNIDENTIFIED: {record['path']}")

    if args.missing:
        print_missing(result["missing"])
        for path in result.get("written", []):
            print(f"  WROTE: {path}")

    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
