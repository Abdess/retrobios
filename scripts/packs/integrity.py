"""Checking a built pack the way the frontend would.

The builder and the verifier have to reach the same verdict on the
same file, so both read the native mode from one place: a pack and a
coverage report that disagree describe different collections."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.artifacts import build_timestamp
from packs.paths import MEDIA_MARKER, has_path_conflict
from core.ziptools import build_zip_contents_index, is_archive_path
from core.ziptools import safe_member_parts
from resolve.nativemode import digest_algorithm, platform_mode
from resolve.validation import (
    baseline_verdict, digest_verdict, inner_rom_check, inner_rom_data_check,
)
from resolve.nativemode import hash_mismatch_excludes_file
import sys
from resolve.cores import filter_systems_by_target
from core.hashing import (
    compute_hashes, file_digest, md5_composite, md5_composite_of, md5sum, parse_hash_list,
    stream_hashes,
)
from core.options import reject_unknown
import io
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
import os
from packs.extras import platform_region_groups
from packs.paths import flat_arcname
from resolve.nativemode import reads_file_contents
from resolve import regions as resolve_regions
from packs import slots
from resolve.localfile import held_record_for
from resolve.packfiles import resolve_declaration, resolve_file
from resolve.categories import BIOS, EntryCategories
from resolve.gamedata import without_game_data
from resolve.cores import resolve_platform_cores
from core.paths import BIOS_DIR, EMULATORS_DIR, declared_destination
import zipfile
from collections.abc import Callable
from pathlib import Path

# Imported at run time where typing has it: a test reads the signature of
# verify_pack_against_platform with its annotations evaluated.
if sys.version_info >= (3, 11):
    from typing import Unpack
elif TYPE_CHECKING:
    from typing_extensions import Unpack


def _members_are_held(data: bytes, by_md5: dict, held_inside: dict) -> bool:
    """Whether every member of an archive is a dump the collection holds."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [i for i in archive.infolist() if not i.is_dir()]
            if not members:
                return False
            for info in members:
                with archive.open(info) as stream:
                    digest = md5sum(stream)
                if digest not in by_md5 and digest not in held_inside:
                    return False
    except (zipfile.BadZipFile, OSError):
        return False
    return True


def _once(build: Callable[[], dict]) -> Callable[[], dict]:
    """A value built on first use and kept."""
    built: list[dict] = []

    def get() -> dict:
        if not built:
            built.append(build())
        return built[0]

    return get


def _settle_untracked(
    status: str,
    name: str,
    zf: zipfile.ZipFile,
    by_md5: dict,
    held_inside: Callable[[], dict],
    errors: list[str],
    file_name: str,
) -> tuple[str, str]:
    """Status of a member no hash recognised, and the name to record.

    An archive the builder assembled (a MAME clone set) passes when every
    member is a dump the collection holds, loose or inside a romset. Bytes
    nothing recognises were written wrong or come from a source that no
    longer matches: counted and passed, they went unseen.
    """
    if status != "untracked":
        return status, file_name
    if name.endswith(".zip") and _members_are_held(zf.read(name), by_md5, held_inside()):
        return "verified_members", os.path.basename(name)
    errors.append(f"{name}: content matches no collected file")
    return "untracked", file_name


def _member_crcs(archive: zipfile.ZipFile) -> dict[str, int]:
    return {i.filename: i.CRC for i in archive.infolist() if not i.is_dir()}


def _same_members(pack: zipfile.ZipFile, name: str, source: str) -> bool:
    """Whether a ZIP inside the pack holds the members of a ZIP on disk.

    A rebuilt archive (TorrentZip) differs byte for byte and is the same
    set when every member and its CRC agree. The two checks that ask it
    each carried their own copy.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(pack.read(name))) as packed, \
                zipfile.ZipFile(source) as held:
            return _member_crcs(packed) == _member_crcs(held)
    except (zipfile.BadZipFile, OSError):
        return False


def _data_indexes(data_registry: dict | None) -> tuple[dict[str, list[str]], dict[str, str]]:
    """The cached data directory files by name and by relative path."""
    _data_index: dict[str, list[str]] = {}
    _data_path_index: dict[str, str] = {}
    if data_registry:
        for _de in data_registry.values():
            cache = _de.get("local_cache", "")
            if not cache or not os.path.isdir(cache):
                continue
            for _r, _d, _fns in os.walk(cache):
                for _fn in _fns:
                    _fp = os.path.join(_r, _fn)
                    _rel = os.path.relpath(_fp, cache)
                    _data_path_index[_rel] = _fp
                    _data_index.setdefault(_fn, []).append(_fp)
    return _data_index, _data_path_index


def _is_pack_note(name: str) -> bool:
    """Whether a member is a note the builder composes, not a collected file."""
    # The builder writes its notes beside the slot they explain
    # (bios/INSTRUCTIONS_x.txt, games/keen6/INSTRUCTIONS_y.txt), so
    # they are told by their own name, not by a root prefix.
    base = name.rsplit("/", 1)[-1]
    return base.startswith(("INSTRUCTIONS_", "RENAMED_")) or base == MEDIA_MARKER or name in (
        "manifest.json",
        "README.txt",
    )


def _member_digests(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[str, str, int]:
    """(sha1, md5, size) of a pack member."""
    with zf.open(info) as f:
        digests = stream_hashes(f, frozenset({"sha1", "md5"}))
    return digests["sha1"], digests["md5"], info.file_size


def _rebuilt_from(zf: zipfile.ZipFile, name: str, by_name: dict, files_db: dict) -> str | None:
    """The name of a held archive a rebuilt ZIP carries the members of."""
    _bn = os.path.basename(name)
    for _src_sha1 in by_name.get(_bn, []):
        if _src_sha1 not in files_db:
            continue
        _src_path = files_db[_src_sha1]["path"]
        if not os.path.exists(_src_path):
            continue
        if _same_members(zf, name, _src_path):
            return _bn
    return None


def _cached_as(
    zf: zipfile.ZipFile,
    name: str,
    size: int,
    sha1: str,
    data_indexes: tuple[dict[str, list[str]], dict[str, str]],
) -> str | None:
    """The name of the data directory file a member is, or None."""
    _data_index, _data_path_index = data_indexes
    _bn = os.path.basename(name)
    _pr = name
    for _known_prefix in ("system/", "bios/", "BIOS/", "Firmware/"):
        if name.startswith(_known_prefix):
            _pr = name[len(_known_prefix):]
            break
    _cands = []
    if _pr in _data_path_index:
        _cands.append(_data_path_index[_pr])
    for _dp in _data_index.get(_bn, []):
        if _dp not in _cands:
            _cands.append(_dp)
    for _dp in _cands:
        if not os.path.exists(_dp):
            continue
        # The content, not the size: a member written corrupt
        # keeps its length, and a same-sized homonym from another
        # cache is another file.
        if os.path.getsize(_dp) == size and compute_hashes(_dp, frozenset({"sha1"}))["sha1"] == sha1:
            return _bn
        if (
            name.endswith(".zip") and _dp.endswith(".zip")
            and _same_members(zf, name, _dp)
        ):
            return _bn
    return None


def verify_pack(
    zip_path: str, db: dict, data_registry: dict | None = None
) -> tuple[bool, dict]:
    """Verify a generated pack ZIP by re-hashing every file inside.

    Checks against database.json, data directory caches, and verifies
    rebuilt ZIP content by comparing inner CRC32s against source.
    Returns (all_ok, manifest_dict).
    """
    files_db = db.get("files", {})  # SHA1 -> file_info
    by_md5 = db.get("indexes", {}).get("by_md5", {})  # MD5 -> SHA1
    # Built on the first archive no hash recognises, once per pack: the
    # index opens every archive of the collection.
    held_inside = _once(lambda: build_zip_contents_index(db))
    by_name = db.get("indexes", {}).get("by_name", {})  # name -> [SHA1]

    # Data directory file index
    data_indexes = _data_indexes(data_registry)

    manifest: dict = {
        "schema_version": 1,
        "version": 1,
        "generator": "retrobios generate_pack.py",
        "generated": build_timestamp(db),
        "files": [],
    }
    errors: list[str] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir() or _is_pack_note(info.filename):
                continue
            name = info.filename
            sha1, md5, size = _member_digests(zf, info)

            # Look up in database: files_db keyed by SHA1
            db_entry = files_db.get(sha1)
            status = "verified"
            file_name = ""
            if db_entry:
                file_name = db_entry.get("name", "")
            else:
                # Try MD5 -> SHA1 lookup
                ref_sha1 = by_md5.get(md5)
                db_entry = files_db.get(ref_sha1) if ref_sha1 else None
                if db_entry:
                    file_name = db_entry.get("name", "")
                    status = "verified_md5"
                else:
                    status = "untracked"

            # Rebuilt ZIP: verify inner ROM CRC32s match source
            if status == "untracked" and name.endswith(".zip"):
                rebuilt = _rebuilt_from(zf, name, by_name, files_db)
                if rebuilt:
                    status = "verified_rebuild"
                    file_name = rebuilt

            # Data directory: check against cached files
            if status == "untracked" and data_indexes[0]:
                cached = _cached_as(zf, name, size, sha1, data_indexes)
                if cached:
                    status = "verified_data"
                    file_name = cached

            status, file_name = _settle_untracked(
                status, name, zf, by_md5, held_inside, errors, file_name
            )

            manifest["files"].append(
                {
                    "path": name,
                    "sha1": sha1,
                    "md5": md5,
                    "size": size,
                    "status": status,
                    "name": file_name,
                }
            )

            # Corruption check: SHA1 in DB but doesn't match what we computed
            # This should never happen (we looked up by SHA1), but catches
            # edge cases where by_md5 resolved to a different SHA1
            if db_entry and status == "verified_md5":
                expected_sha1 = db_entry.get("sha1", "")
                if expected_sha1 and expected_sha1.lower() != sha1.lower():
                    errors.append(
                        f"{name}: SHA1 mismatch (expected {expected_sha1}, got {sha1})"
                    )

    verified = sum(1 for f in manifest["files"] if f["status"].startswith("verified"))
    untracked = sum(1 for f in manifest["files"] if f["status"] == "untracked")
    total = len(manifest["files"])
    manifest["summary"] = {
        "total_files": total,
        "verified": verified,
        "untracked": untracked,
        "errors": len(errors),
    }
    manifest["errors"] = errors

    all_ok = len(errors) == 0
    return all_ok, manifest

def generate_sha256sums(output_dir: str) -> str | None:
    """Generate SHA256SUMS.txt for all ZIP files in output_dir."""
    sums_path = os.path.join(output_dir, "SHA256SUMS.txt")
    entries = []
    for name in sorted(os.listdir(output_dir)):
        if not name.endswith(".zip"):
            continue
        path = os.path.join(output_dir, name)
        entries.append(f"{file_digest(Path(path), 'sha256')}  {name}")
    if not entries:
        return None
    with open(sums_path, "w") as f:
        f.write("\n".join(entries) + "\n")
    print(f"\n{sums_path}: {len(entries)} pack checksums")
    return sums_path

def _check_member_hash(
    zf: zipfile.ZipFile, member: str, file_entry: dict, mode: str, rule: str = ""
) -> str | None:
    """Verify a pack member against its platform-declared hash.

    Reproduces the platform's native check inside the pack: md5/sha1 of
    the member bytes, or checkInsideZip when zipped_file is set
    (Batocera hashes a ROM inside the ZIP, matched case-insensitively).
    Returns an error string, or None when the member passes.
    """
    zipped_file = file_entry.get("zipped_file")
    if zipped_file:
        # checkInsideZip runs with an empty md5 too, and needs the member.
        verdict = inner_rom_data_check(file_entry, zf.read(member))
        if verdict == "ok":
            return None
        if verdict == "not_in_zip":
            return f"{member}: {zipped_file} not found inside ZIP"
        if verdict == "error":
            return f"{member}: {zipped_file} unreadable inside ZIP"
        return (
            f"{member}: {zipped_file} inside-zip md5 != declared "
            f"{', '.join(parse_hash_list(file_entry.get('md5')))}"
        )

    declared = str(file_entry.get(mode) or "").strip()
    if not declared:
        return None

    # The frontend's own rule, as the builder and verify apply it: RomM's
    # size-then-any-hash included, which a bare md5 comparison refused.
    with zf.open(member) as f:
        computed = stream_hashes(f, frozenset({"md5", "sha1", "crc32"}))

    def composite() -> str | None:
        # Recalbox's Md5Composite, over the sorted members of a ZIP.
        if not member.endswith(".zip"):
            return None
        import io

        try:
            return md5_composite_of(io.BytesIO(zf.read(member)))
        except (zipfile.BadZipFile, OSError) as exc:
            print(f"  {member}: no member digest ({exc})", file=sys.stderr)
            return None

    if digest_verdict(
        file_entry, zf.getinfo(member).file_size, lambda: computed, mode, rule, composite
    ):
        return None
    return f"{member}: {mode} {computed[mode]} != declared {declared}"

def _repo_satisfies_declaration(
    entries: list[dict], db: dict, mode: str
) -> bool:
    """Check whether any repo file matches one of the declarations.

    Used to separate pack divergence (a matching file exists but was not
    packed) from data coverage gaps (no repo file matches the upstream
    declaration): only the former is a pack generation error. A held file
    is the resolver's: every declared hash agrees with it, and a zipped_file
    md5 names a member of a held archive, not a loose file. The verdict
    compares whole digests as the frontend does, so a cut md5 names a held
    file without being satisfied by it.
    """
    files_db = db.get("files", {})
    by_name = db.get("indexes", {}).get("by_name", {})

    for fe in entries:
        if fe.get("zipped_file"):
            if _repo_holds_member(fe, db):
                return True
            continue
        hashes = parse_hash_list(fe.get(mode))
        if not hashes:
            continue
        held_sha1 = held_record_for(fe, db)
        if held_sha1 is not None:
            held = files_db[held_sha1]
            digest = held_sha1 if mode == "sha1" else str(held.get(mode, ""))
            if digest.lower() in hashes and os.path.exists(held.get("path", "")):
                return True
        if mode == "md5":
            hash_set = set(hashes)
            for cand_sha in by_name.get(fe.get("name", ""), []):
                entry = files_db.get(cand_sha)
                if not entry:
                    continue
                path = entry.get("path", "")
                if not is_archive_path(path) or not os.path.exists(path):
                    continue
                try:
                    if md5_composite(path).lower() in hash_set:
                        return True
                except (zipfile.BadZipFile, OSError):
                    continue
    return False

def _repo_holds_member(file_entry: dict, db: dict) -> bool:
    """Whether a held archive of that name carries the declared member."""
    files_db = db.get("files", {})
    for sha1 in db.get("indexes", {}).get("by_name", {}).get(file_entry.get("name", ""), []):
        path = (files_db.get(sha1) or {}).get("path", "")
        if not is_archive_path(path) or not os.path.exists(path):
            continue
        if inner_rom_check(file_entry, path) == "ok":
            return True
    return False


def _held_nowhere(
    entries: list[dict],
    db: dict,
    zip_contents: dict,
    data_dir_registry: dict | None,
) -> bool:
    """Return whether no declaration for a destination resolves to a file."""
    return bool(entries) and all(
        resolve_file(
            entry,
            db,
            BIOS_DIR,
            zip_contents,
            data_dir_registry=data_dir_registry,
            offline=True,
        )[1] == "not_found"
        for entry in entries
    )


def _intentional_hash_exclusion(
    entries: list[dict],
    db: dict,
    bios_dir: str = BIOS_DIR,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
    verification_mode: str = "md5",
    hash_rule: str = "",
) -> bool:
    """Return whether the builder must omit every declaration as unsafe.

    A hash platform never substitutes a same-named payload for an explicitly
    hash-identified one, so a missing pack member is accounted for when every
    declaration for that destination resolves to a local hash mismatch.  An
    existence platform reads no bytes and the builder ships the file anyway,
    so nothing is ever excluded on its behalf.  Genuine absence,
    external-download failure and a packable alternative stay conformance
    errors in both modes.
    """
    if not entries or not hash_mismatch_excludes_file(verification_mode):
        return False
    archive_index = zip_contents if zip_contents is not None else {}
    for entry in entries:
        local_path, status = resolve_file(
            entry,
            db,
            bios_dir,
            archive_index,
            data_dir_registry=data_dir_registry,
            offline=True,
        )
        # The builder's own verdict: a zipped_file archive is refused when the
        # member is missing whatever the outer resolution said, a hash
        # mismatch when the frontend's digest disagrees too.
        _status, refusal = baseline_verdict(
            entry, local_path, status, verification_mode, hash_rule
        )
        if refusal is None:
            return False
    return True

def _structural_errors(zf: zipfile.ZipFile, zip_set: set) -> list[str]:
    """Faults in the archive itself, before any file is looked up.

    A duplicate entry, an absolute path or a traversal makes the pack
    unsafe to extract whatever it contains, and a zero-byte member is a
    file the user will believe they have. The markers Dolphin ships for
    its graphics mods are legitimately empty.
    """
    errors: list[str] = []
    # Structural checks
    dupes = sum(1 for c in Counter(zf.namelist()).values() if c > 1)
    if dupes:
        errors.append(f"{dupes} duplicate entries")
    errors.extend(f"double slash: {n}" for n in zip_set if "//" in n)
    for info in zf.infolist():
        try:
            safe_member_parts(info)
        except ValueError as exc:
            errors.append(str(exc))

    # Zero-byte check (exclude Dolphin GraphicMods markers)
    errors.extend(
        f"zero-byte: {info.filename}"
        for info in zf.infolist()
        if info.file_size == 0 and not info.is_dir()
        and "GraphicMods" not in info.filename
        and info.filename not in ("manifest.json", "README.txt")
        and info.filename.rsplit("/", 1)[-1] != MEDIA_MARKER
    )

    return errors


def _shipped_copy(
    entry: dict, db: dict, data_registry: dict | None, mode: str, hash_rule: str,
) -> str | None:
    """The file the builder packs for a declaration, or None.

    The verdict verify applies before it lets a declaration hold its path.
    """
    local, status = resolve_declaration(
        entry, db, BIOS_DIR, None, data_registry, None, offline=True,
    )
    if local and baseline_verdict(entry, local, status, mode, hash_rule)[1] is None:
        return local
    return None


def _builder_extras(
    expect: _Expectation,
    db: dict,
    baseline_groups: dict[str, list[dict]],
    view: _PackView,
    include_all: bool = False,
) -> dict[str, str]:
    """{full destination: local copy} of each core extra the builder writes.

    The platform's paths come first, as in the builder: a destination the
    pack holds whose declarations resolve to a file it ships, or that the
    platform keeps for a user_provided or external entry. One whose
    declarations resolve to nothing, or to a file the frontend's hash
    refuses, is left free, since the builder then places a core's file
    there: taken by the refused file, that core file was never compared.
    """
    from packs.extras import ExtraResolver, hidden_extras
    from resolve.validation import build_validation_index, destination_owners

    config, emu_profiles = expect.config, expect.emu_profiles
    data_registry = expect.opts.data_registry
    base_dest = expect.base_dest
    mode = platform_mode(config)
    hash_rule = config.get("hash_rule", "")
    shipped: dict[str, str | None] = {}
    for expected, declarations in baseline_groups.items():
        if not view.holds(expected):
            continue
        unflat = (
            f"{base_dest}/{expected}"
            if view.is_flat and base_dest and not expected.startswith(f"{base_dest}/")
            else expected
        )
        if any(fe.get("storage") in ("user_provided", "external") for fe in declarations):
            shipped[unflat] = None
            continue
        local = next(
            (
                found for fe in declarations
                if (found := _shipped_copy(fe, db, data_registry, mode, hash_rule))
            ),
            None,
        )
        if local:
            shipped[unflat] = local
    platform_profiles = {
        name: emu_profiles[name] for name in resolve_platform_cores(config, emu_profiles)
    }
    placed_local: dict[str, str] = {}
    hidden_extras(
        config, expect.opts.emulators_dir, db, emu_profiles, shipped, expect.target_cores,
        expect.region_drops or None,
        resolver=ExtraResolver(
            db, BIOS_DIR, build_zip_contents_index(db), data_registry,
            build_validation_index(platform_profiles),
            destination_owners(platform_profiles), True, profiles=emu_profiles,
        ),
        placed_local=placed_local,
        include_all=include_all,
        required_only=expect.opts.required_only,
    )
    return placed_local


def _same_content(zf: zipfile.ZipFile, member: str, local: str) -> bool:
    """Whether a pack member carries the bytes of a local copy, or the
    members of an archive the builder normalized."""
    with open(local, "rb") as handle:
        if zf.read(member) == handle.read():
            return True
    return local.lower().endswith(".zip") and _same_members(zf, member, local)


class PlatformCheckOptions(TypedDict, total=False):
    """The keyword options of verify_pack_against_platform."""

    emulators_dir: str
    emu_profiles: dict | None
    regions: list[str] | None
    data_registry: dict | None
    source: str
    required_only: bool
    no_game_data: bool


@dataclass(frozen=True)
class _PlatformCheckSettings:
    """PlatformCheckOptions with their defaults."""

    emulators_dir: str = EMULATORS_DIR
    emu_profiles: dict | None = None
    regions: list[str] | None = None
    data_registry: dict | None = None
    source: str = "full"
    required_only: bool = False
    no_game_data: bool = False


@dataclass(frozen=True)
class _Expectation:
    """What the builder would have packed for a platform, before the pack is read."""

    config: dict
    emu_profiles: dict
    expected_systems: dict
    region_drops: set[str]
    db: dict | None
    target_cores: set[str] | None
    opts: _PlatformCheckSettings

    @property
    def base_dest(self) -> str:
        return self.config.get("base_destination", "")


@dataclass(frozen=True)
class _PackView:
    """A pack's member names as the checks read them."""

    zf: zipfile.ZipFile
    zip_set: set[str]
    zip_lower: dict[str, str]
    zip_parents: set[str]
    is_flat: bool

    def holds(self, expected: str) -> bool:
        return expected in self.zip_set or expected.lower() in self.zip_lower


@dataclass
class _BaselineCount:
    """The baseline destinations checked, and what each came to."""

    checked: int = 0
    present: int = 0
    excluded: int = 0
    absent: int = 0
    decl_by_member: dict[str, list[dict]] = field(default_factory=dict)


def _cut_config(
    platform_name: str,
    platforms_dir: str,
    target_cores: set[str] | None,
    opts: _PlatformCheckSettings,
) -> tuple[dict, dict]:
    """The platform's config and the profiles, without game data when asked."""
    config = load_platform_config(platform_name, platforms_dir)
    emu_profiles = opts.emu_profiles
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(opts.emulators_dir)
    if opts.no_game_data:
        cut = without_game_data(config, emu_profiles, opts.data_registry, target_cores)
        config, emu_profiles = cut.config, cut.profiles
    return config, emu_profiles


def _region_drops(
    config: dict,
    emu_profiles: dict,
    expected_systems: dict,
    db: dict | None,
    *,
    target_cores: set[str] | None,
    opts: _PlatformCheckSettings,
) -> set[str]:
    """The regional variants the builder leaves out, by the same selection."""
    region_drops: set[str] = set()
    if not opts.regions:
        return region_drops
    region_index = resolve_regions.platform_region_index(
        config, emu_profiles, target_cores
    )
    held: set[str] = set()
    held_zip_contents = build_zip_contents_index(db) if db is not None else {}
    region_groups, _extra_dests = platform_region_groups(
        config,
        expected_systems,
        opts.emulators_dir,
        db,
        config.get("base_destination", ""),
        emu_profiles,
        target_cores=target_cores,
        include_extras=(opts.source != "platform"),
        include_all=(opts.source == "truth"),
        required_only=opts.required_only,
        held_out=held,
        zip_contents=held_zip_contents,
        data_registry=opts.data_registry,
        slot_overrides=slots.pack_overrides(
            config, emu_profiles, db, held_zip_contents, opts.data_registry,
            target_cores=target_cores, source=opts.source,
        ) if db is not None else None,
    )
    return resolve_regions.resolve_region_drops(
        region_groups, region_index, opts.regions, held
    )


def _pack_view(zf: zipfile.ZipFile, config: dict, base_dest: str) -> _PackView:
    zip_set = set(zf.namelist())
    # A case twin stands in for the file only where the platform's
    # filesystem folds case, as the builder decides: on Lakka bios.col
    # and BIOS.col are two files two cores open, and either one missing
    # was counted present through the other.
    zip_lower = (
        {n.lower(): n for n in zip_set}
        if config.get("case_insensitive_fs", False) else {}
    )

    # Auto-detect flat vs nested ZIP
    is_flat = bool(base_dest) and not any(
        n.startswith(base_dest + "/")
        for n in zip_set
        if n not in ("README.txt", "manifest.json", MEDIA_MARKER) and not n.endswith("/")
    )
    # Mirror the builder's path-conflict logic: a declaration whose path
    # collides file-vs-directory with a packed member was skipped by the
    # builder (upstream declares e.g. both SGB1.sfc and SGB1.sfc/program.rom)
    zip_parents: set[str] = set()
    for n in zip_set:
        parts = n.split("/")
        for i in range(1, len(parts)):
            zip_parents.add("/".join(parts[:i]))
    return _PackView(zf, zip_set, zip_lower, zip_parents, is_flat)


def _baseline_groups(
    expect: _Expectation, is_flat: bool,
) -> tuple[dict[str, list[dict]], dict[int, str]]:
    """The platform's declarations by the path they expect in the pack, and
    the system of each declaration."""
    opts = expect.opts
    base_dest = expect.base_dest
    baseline_groups: dict[str, list[dict]] = {}
    system_of: dict[int, str] = {}
    for sys_id, system in (expect.expected_systems if opts.source != "truth" else {}).items():
        for fe in system.get("files", []):
            system_of[id(fe)] = sys_id
            if opts.required_only and fe.get("required") is False:
                continue
            dest = declared_destination(fe)
            if not dest:
                continue
            if expect.region_drops and dest in expect.region_drops:
                continue
            expected = f"{base_dest}/{dest}" if base_dest and not is_flat else dest
            baseline_groups.setdefault(expected, []).append(fe)
    return baseline_groups, system_of


def _count_baseline(
    expect: _Expectation,
    view: _PackView,
    baseline_groups: dict[str, list[dict]],
    system_of: dict[int, str],
    errors: list[str],
) -> _BaselineCount:
    """Each baseline destination present, accounted for, or missing."""
    db = expect.db
    data_registry = expect.opts.data_registry
    count = _BaselineCount(checked=len(baseline_groups))
    # RetroBat's group: one packed file of it is enough, as verify counts it.
    packed_groups = {
        (system_of[id(fe)], fe["group"])
        for expected, declarations in baseline_groups.items()
        if view.holds(expected)
        for fe in declarations
        if fe.get("group")
    }
    exclusion_index = build_zip_contents_index(db) if db is not None else {}
    categories = EntryCategories(expect.config, expect.emu_profiles, data_registry)
    for expected, declarations in baseline_groups.items():
        if expected in view.zip_set:
            member = expected
        elif expected.lower() in view.zip_lower:
            member = view.zip_lower[expected.lower()]
        elif has_path_conflict(expected, view.zip_set, view.zip_parents):
            # Skipped by the builder for the same reason: not an error
            count.present += 1
            continue
        elif db is not None and _intentional_hash_exclusion(
            declarations,
            db,
            zip_contents=exclusion_index,
            data_dir_registry=data_registry,
            verification_mode=platform_mode(expect.config),
            hash_rule=expect.config.get("hash_rule", ""),
        ):
            count.excluded += 1
            continue
        elif all(
            fe.get("group") and (system_of[id(fe)], fe["group"]) in packed_groups
            for fe in declarations
        ):
            count.absent += 1
            continue
        elif db is not None and all(
            categories.category(fe, fe.get("destination", fe.get("name", "")),
                                system_of[id(fe)]) != BIOS
            for fe in declarations
        ) and _held_nowhere(declarations, db, exclusion_index, data_registry):
            # A game's data or an entry no core opens that the collection
            # lacks: verify counts it apart. Missing firmware stays an error.
            count.absent += 1
            continue
        else:
            errors.append(f"baseline missing: {expected}")
            continue
        count.present += 1
        count.decl_by_member.setdefault(member, []).extend(declarations)
    return count


def _native_hash_errors(
    zf: zipfile.ZipFile, decl_by_member: dict[str, list[dict]], config: dict, db: dict | None,
) -> list[str]:
    """The platform's native hash check replayed on the pack's bytes."""
    # Reproduce the platform's native hash check on pack bytes.
    # A destination declared by several entries passes when the packed
    # member satisfies any of them. A failure only counts as a pack
    # error when the repo holds a file matching a declaration: without
    # one, the pack ships its best effort and the gap is a data issue
    # reported by verify.py, not a generation bug.
    verification_mode = platform_mode(config)
    digest = digest_algorithm(verification_mode)
    hash_rule = config.get("hash_rule", "")
    errors: list[str] = []
    if not (reads_file_contents(verification_mode) and digest):
        return errors
    for member, decl_entries in decl_by_member.items():
        checkable = [
            fe
            for fe in decl_entries
            if fe.get("zipped_file") or str(fe.get(digest) or "").strip()
        ]
        if not checkable:
            continue
        # An archive declared once per ROM it must hold is checked
        # once per ROM by the frontend: each such declaration has to
        # pass on its own, where the repository holds an archive
        # that would.
        for fe in checkable:
            if not fe.get("zipped_file"):
                continue
            err = _check_member_hash(zf, member, fe, digest, hash_rule)
            if err is not None and (db is None or _repo_holds_member(fe, db)):
                errors.append(err)
        member_errors = []
        satisfied = False
        for fe in checkable:
            err = _check_member_hash(zf, member, fe, digest, hash_rule)
            if err is None:
                satisfied = True
                break
            member_errors.append(err)
        if satisfied:
            continue
        if db is None or _repo_satisfies_declaration(
            checkable, db, verification_mode
        ):
            errors.append(member_errors[0])
    return errors


def _check_core_extras(
    expect: _Expectation,
    view: _PackView,
    baseline_groups: dict[str, list[dict]],
    errors: list[str],
) -> tuple[int, int]:
    """(checked, present) of the core extras the builder places."""
    # 2. Core extras: the builder's own placement replayed
    #    (packextras.hidden_extras, which verify reads too), after the
    #    platform files it wrote. Each placed extra must sit at its path
    #    with the bytes the builder resolved: an empty seen set and a
    #    presence test credited a core file at a path where the pack
    #    holds the platform's other dump.
    core_checked = 0
    core_present = 0
    opts = expect.opts
    db = expect.db
    if db is None or opts.source == "platform":
        return core_checked, core_present
    placed_local = _builder_extras(
        expect, db, baseline_groups, view, include_all=(opts.source == "truth"),
    )
    for full, local in sorted(placed_local.items()):
        core_checked += 1
        flat = flat_arcname(full, expect.base_dest, view.is_flat)
        member = flat if flat in view.zip_set else view.zip_lower.get(flat.lower())
        if member is None:
            errors.append(f"core missing: {full}")
        elif not _same_content(view.zf, member, local):
            errors.append(
                f"core file differs: {member} is not the {os.path.basename(local)}"
                " the builder places there"
            )
        else:
            core_present += 1
    return core_checked, core_present


def verify_pack_against_platform(
    zip_path: str,
    platform_name: str,
    platforms_dir: str,
    db: dict | None = None,
    *,
    target_cores: set[str] | None = None,
    **options: Unpack[PlatformCheckOptions],
) -> tuple[bool, int, int, list[str], int, int, int, int, int, int]:
    """Verify a pack ZIP against its platform config and core requirements.

    A region priority list narrows the expectation to what the builder would
    have packed, using the same selection function. A hardware target narrows
    it the same way and for the same reason: the systems it removes are not
    missing from the pack, they were never asked for. ``source`` and
    ``required_only`` are the variant the pack was built as: a platform-only
    pack is held to the platform's list alone, a truth pack to the cores'
    files alone, and a required-only pack to the required entries of both.
    ``no_game_data`` holds the pack to the firmware alone, cut as the
    builder cuts it.

    Checks:
    1. Every baseline file declared by the platform exists in the ZIP
       at the correct destination path
    2. Every in-repo core extra file (from emulator profiles) is present
    3. No duplicate entries
    4. No path anomalies (double slash, absolute, traversal)
    5. No unexpected zero-byte BIOS files

    Returns ``(all_ok, checked, present, errors, baseline_checked,
    baseline_present, core_checked, core_present, baseline_excluded,
    baseline_absent)``. ``baseline_absent`` counts destinations the collection
    holds no file for that are a game's data or that no core the platform
    runs opens. verify.py counts them apart from firmware.
    """
    reject_unknown(
        "verify_pack_against_platform", options, PlatformCheckOptions.__optional_keys__
    )
    opts = _PlatformCheckSettings(**options)
    config, emu_profiles = _cut_config(platform_name, platforms_dir, target_cores, opts)
    expected_systems = config.get("systems", {})
    if target_cores is not None:
        expected_systems = filter_systems_by_target(
            expected_systems,
            emu_profiles,
            target_cores,
            resolve_platform_cores(config, emu_profiles),
        )
    expect = _Expectation(
        config, emu_profiles, expected_systems,
        _region_drops(
            config, emu_profiles, expected_systems, db,
            target_cores=target_cores, opts=opts,
        ),
        db, target_cores, opts,
    )
    errors: list[str] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        view = _pack_view(zf, expect.config, expect.base_dest)
        errors.extend(_structural_errors(zf, view.zip_set))

        # 1. Baseline file presence + native hash check
        baseline_groups, system_of = _baseline_groups(expect, view.is_flat)
        baseline = _count_baseline(expect, view, baseline_groups, system_of, errors)
        errors.extend(_native_hash_errors(zf, baseline.decl_by_member, expect.config, db))
        core_checked, core_present = _check_core_extras(expect, view, baseline_groups, errors)

    return (
        len(errors) == 0,
        baseline.checked + core_checked,
        baseline.present + core_present,
        errors,
        baseline.checked,
        baseline.present,
        core_checked,
        core_present,
        baseline.excluded,
        baseline.absent,
    )
