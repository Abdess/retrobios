"""Checking a built pack the way the frontend would.

The builder and the verifier have to reach the same verdict on the
same file, so both read the native mode from one place: a pack and a
coverage report that disagree describe different collections."""

from __future__ import annotations

from collections import Counter

from auto_fetch import DEFAULT_BIOS_DIR
from artifacts import _build_timestamp
from packpaths import MEDIA_MARKER, _has_path_conflict
from ziptools import build_zip_contents_index
from ziptools import check_inside_zip
from nativemode import digest_algorithm
from validation import baseline_verdict, digest_verdict
from nativemode import hash_mismatch_excludes_file
import functools
import hashlib
import zlib
import sys
from common import filter_systems_by_target
from hashing import md5_composite_of, parse_md5_list
import io
from common import load_emulator_profiles
from common import load_platform_config
import os
from packextras import platform_region_groups
from packpaths import _flat
from nativemode import reads_file_contents
import region as region_mod
import slots
from packresolve import resolve_declaration, resolve_file
from exporter.candidates import BIOS, EntryCategories
from gamedata import without_game_data
from common import resolve_platform_cores
from common import sanitize_pack_path
import zipfile
from collections.abc import Callable


@functools.lru_cache(maxsize=None)
def _file_sha1(path: str) -> str:
    """SHA-1 of a cached data-directory file, read once per run."""
    digest = hashlib.sha1()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _members_are_held(data: bytes, by_md5: dict, held_inside: dict) -> bool:
    """Whether every member of an archive is a dump the collection holds."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [i for i in archive.infolist() if not i.is_dir()]
            if not members:
                return False
            for info in members:
                digest = hashlib.md5(archive.read(info)).hexdigest()
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
    _data_index: dict[str, list[str]] = {}
    _data_path_index: dict[str, str] = {}
    if data_registry:
        for _dk, _de in data_registry.items():
            cache = _de.get("local_cache", "")
            if not cache or not os.path.isdir(cache):
                continue
            for _r, _d, _fns in os.walk(cache):
                for _fn in _fns:
                    _fp = os.path.join(_r, _fn)
                    _rel = os.path.relpath(_fp, cache)
                    _data_path_index[_rel] = _fp
                    _data_index.setdefault(_fn, []).append(_fp)

    manifest = {
        "schema_version": 1,
        "version": 1,
        "generator": "retrobios generate_pack.py",
        "generated": _build_timestamp(db),
        "files": [],
    }
    errors = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            # The builder writes its notes beside the slot they explain
            # (bios/INSTRUCTIONS_x.txt, games/keen6/INSTRUCTIONS_y.txt), so
            # they are told by their own name, not by a root prefix.
            base = name.rsplit("/", 1)[-1]
            if base.startswith(("INSTRUCTIONS_", "RENAMED_")) or base == MEDIA_MARKER or name in (
                "manifest.json",
                "README.txt",
            ):
                continue
            with zf.open(info) as f:
                sha1_h = hashlib.sha1()
                md5_h = hashlib.md5()
                size = 0
                for chunk in iter(lambda: f.read(65536), b""):
                    sha1_h.update(chunk)
                    md5_h.update(chunk)
                    size += len(chunk)
            sha1 = sha1_h.hexdigest()
            md5 = md5_h.hexdigest()

            # Look up in database: files_db keyed by SHA1
            db_entry = files_db.get(sha1)
            status = "verified"
            file_name = ""
            if db_entry:
                file_name = db_entry.get("name", "")
            else:
                # Try MD5 -> SHA1 lookup
                ref_sha1 = by_md5.get(md5)
                if ref_sha1:
                    db_entry = files_db.get(ref_sha1)
                    if db_entry:
                        file_name = db_entry.get("name", "")
                        status = "verified_md5"
                    else:
                        status = "untracked"
                else:
                    status = "untracked"

            # Rebuilt ZIP: verify inner ROM CRC32s match source
            if status == "untracked" and name.endswith(".zip"):
                _bn = os.path.basename(name)
                for _src_sha1 in by_name.get(_bn, []):
                    if _src_sha1 not in files_db:
                        continue
                    _src_path = files_db[_src_sha1]["path"]
                    if not os.path.exists(_src_path):
                        continue
                    if _same_members(zf, name, _src_path):
                        status = "verified_rebuild"
                        file_name = _bn
                        break

            # Data directory: check against cached files
            if status == "untracked" and _data_index:
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
                    if os.path.getsize(_dp) == size and _file_sha1(_dp) == sha1:
                        status = "verified_data"
                        file_name = _bn
                        break
                    if (
                        name.endswith(".zip") and _dp.endswith(".zip")
                        and _same_members(zf, name, _dp)
                    ):
                        status = "verified_data"
                        file_name = _bn
                        break

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
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        entries.append(f"{sha256.hexdigest()}  {name}")
    if not entries:
        return None
    with open(sums_path, "w") as f:
        f.write("\n".join(entries) + "\n")
    print(f"\n{sums_path}: {len(entries)} pack checksums")
    return sums_path

def _hash_matches(declared: str, actual: str) -> bool:
    """Compare a declared hash value against an actual hex digest.

    Handles comma-separated multi-hash lists and uppercase (Recalbox)
    and MD5s shorter than 32 characters: a declared value shorter than
    the digest matches by prefix.
    """
    actual = actual.lower()
    for cand in declared.split(","):
        cand = cand.strip().lower()
        if not cand:
            continue
        if len(cand) < len(actual):
            if actual.startswith(cand):
                return True
        elif actual == cand:
            return True
    return False

def _check_member_hash(
    zf: zipfile.ZipFile, member: str, file_entry: dict, mode: str, rule: str = ""
) -> str | None:
    """Verify a pack member against its platform-declared hash.

    Reproduces the platform's native check inside the pack: md5/sha1 of
    the member bytes, or checkInsideZip when zipped_file is set
    (Batocera hashes a ROM inside the ZIP, matched case-insensitively).
    Returns an error string, or None when the member passes.
    """
    declared = str(file_entry.get(mode) or "").strip()
    if not declared:
        return None

    zipped_file = file_entry.get("zipped_file")
    if zipped_file:
        import io

        try:
            with zipfile.ZipFile(io.BytesIO(zf.read(member))) as inner:
                want = zipped_file.casefold()
                target = next(
                    (n for n in inner.namelist() if n.casefold() == want), None
                )
                if target is None:
                    return f"{member}: {zipped_file} not found inside ZIP"
                actual = hashlib.md5(inner.read(target)).hexdigest()
        except zipfile.BadZipFile:
            return f"{member}: not a valid ZIP"
        if not _hash_matches(declared, actual):
            return (
                f"{member}: {zipped_file} inside-zip md5 {actual} "
                f"!= declared {declared}"
            )
        return None

    # The frontend's own rule, as the builder and verify apply it: RomM's
    # size-then-any-hash included, which a bare md5 comparison refused.
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1()}
    crc = 0
    with zf.open(member) as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for h in digests.values():
                h.update(chunk)
            crc = zlib.crc32(chunk, crc)
    actual = {name: h.hexdigest() for name, h in digests.items()}
    actual["crc32"] = format(crc & 0xFFFFFFFF, "08x")

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
        file_entry, zf.getinfo(member).file_size, lambda: actual, mode, rule, composite
    ):
        return None
    return f"{member}: {mode} {actual[mode]} != declared {declared}"

def _repo_satisfies_declaration(
    entries: list[dict], db: dict, mode: str
) -> bool:
    """Check whether any repo file matches one of the declared hashes.

    Used to separate pack divergence (a matching file exists but was not
    packed) from data coverage gaps (no repo file matches the upstream
    declaration): only the former is a pack generation error.
    """
    from common import md5_composite

    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_name = db.get("indexes", {}).get("by_name", {})

    for fe in entries:
        declared = str(fe.get(mode) or "").strip()
        if not declared:
            continue
        hashes = [h.strip().lower() for h in declared.split(",") if h.strip()]
        for h in hashes:
            if mode == "sha1":
                entry = files_db.get(h)
            else:
                entry = files_db.get(by_md5.get(h, ""))
            if entry and os.path.exists(entry.get("path", "")):
                return True
        if mode == "md5":
            hash_set = set(hashes)
            for cand_sha in by_name.get(fe.get("name", ""), []):
                entry = files_db.get(cand_sha)
                if not entry:
                    continue
                path = entry.get("path", "")
                if not path.endswith(".zip") or not os.path.exists(path):
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
    declared = parse_md5_list(file_entry.get("md5"))
    for sha1 in db.get("indexes", {}).get("by_name", {}).get(file_entry.get("name", ""), []):
        path = (files_db.get(sha1) or {}).get("path", "")
        if not path.endswith(".zip") or not os.path.exists(path):
            continue
        if any(check_inside_zip(path, file_entry["zipped_file"], m) == "ok" for m in declared):
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
            DEFAULT_BIOS_DIR,
            zip_contents,
            data_dir_registry=data_dir_registry,
            offline=True,
        )[1] == "not_found"
        for entry in entries
    )


def _intentional_hash_exclusion(
    entries: list[dict],
    db: dict,
    bios_dir: str = DEFAULT_BIOS_DIR,
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
    for n in zip_set:
        if "//" in n:
            errors.append(f"double slash: {n}")
        if n.startswith("/"):
            errors.append(f"absolute path: {n}")
        if ".." in n:
            errors.append(f"path traversal: {n}")

    # Zero-byte check (exclude Dolphin GraphicMods markers)
    for info in zf.infolist():
        if info.file_size == 0 and not info.is_dir():
            if "GraphicMods" not in info.filename and info.filename not in (
                "manifest.json",
                "README.txt",
            ) and info.filename.rsplit("/", 1)[-1] != MEDIA_MARKER:
                errors.append(f"zero-byte: {info.filename}")

    return errors


def _shipped_copy(
    entry: dict, db: dict, data_registry: dict | None, mode: str, hash_rule: str,
) -> str | None:
    """The file the builder packs for a declaration, or None.

    The verdict verify applies before it lets a declaration hold its path.
    """
    local, status = resolve_declaration(
        entry, db, DEFAULT_BIOS_DIR, None, data_registry, None, offline=True,
    )
    if local and baseline_verdict(entry, local, status, mode, hash_rule)[1] is None:
        return local
    return None


def _builder_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    emu_profiles: dict,
    baseline_groups: dict[str, list[dict]],
    base_dest: str,
    is_flat: bool,
    zip_set: set[str],
    zip_lower: dict[str, str],
    target_cores: set[str] | None,
    region_drops: set[str],
    data_registry: dict | None,
    include_all: bool = False,
    required_only: bool = False,
) -> dict[str, str]:
    """{full destination: local copy} of each core extra the builder writes.

    The platform's paths come first, as in the builder: a destination the
    pack holds whose declarations resolve to a file it ships, or that the
    platform keeps for a user_provided or external entry. One whose
    declarations resolve to nothing, or to a file the frontend's hash
    refuses, is left free, since the builder then places a core's file
    there: taken by the refused file, that core file was never compared.
    """
    from packextras import ExtraResolver, hidden_extras
    from validation import _build_validation_index, destination_owners

    mode = config.get("verification_mode", "existence")
    hash_rule = config.get("hash_rule", "")
    shipped: dict[str, str | None] = {}
    for expected, declarations in baseline_groups.items():
        if expected not in zip_set and expected.lower() not in zip_lower:
            continue
        unflat = (
            f"{base_dest}/{expected}"
            if is_flat and base_dest and not expected.startswith(f"{base_dest}/")
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
        config, emulators_dir, db, emu_profiles, shipped, target_cores,
        region_drops or None,
        resolver=ExtraResolver(
            db, DEFAULT_BIOS_DIR, build_zip_contents_index(db), data_registry,
            _build_validation_index(platform_profiles),
            destination_owners(platform_profiles), True, profiles=emu_profiles,
        ),
        placed_local=placed_local,
        include_all=include_all,
        required_only=required_only,
    )
    return placed_local


def _same_content(zf: zipfile.ZipFile, member: str, local: str) -> bool:
    """Whether a pack member carries the bytes of a local copy, or the
    members of an archive the builder normalized."""
    with open(local, "rb") as handle:
        if zf.read(member) == handle.read():
            return True
    return local.lower().endswith(".zip") and _same_members(zf, member, local)


def verify_pack_against_platform(
    zip_path: str,
    platform_name: str,
    platforms_dir: str,
    db: dict | None = None,
    emulators_dir: str = "emulators",
    emu_profiles: dict | None = None,
    regions: list[str] | None = None,
    data_registry: dict | None = None,
    target_cores: set[str] | None = None,
    source: str = "full",
    required_only: bool = False,
    no_game_data: bool = False,
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

    config = load_platform_config(platform_name, platforms_dir)
    base_dest = config.get("base_destination", "")
    errors: list[str] = []
    checked = 0
    present = 0

    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)
    if no_game_data:
        cut = without_game_data(config, emu_profiles, data_registry, target_cores)
        config, emu_profiles = cut.config, cut.profiles

    expected_systems = config.get("systems", {})
    if target_cores is not None:
        expected_systems = filter_systems_by_target(
            expected_systems,
            emu_profiles,
            target_cores,
            resolve_platform_cores(config, emu_profiles),
        )

    region_drops: set[str] = set()
    if regions:
        region_index = region_mod.platform_region_index(
            config, emu_profiles, target_cores
        )
        held: set[str] = set()
        held_zip_contents = build_zip_contents_index(db) if db is not None else {}
        region_groups, _extra_dests = platform_region_groups(
            config,
            expected_systems,
            emulators_dir,
            db,
            base_dest,
            emu_profiles,
            target_cores=target_cores,
            include_extras=(source != "platform"),
            include_all=(source == "truth"),
            required_only=required_only,
            held_out=held,
            zip_contents=held_zip_contents,
            data_registry=data_registry,
            slot_overrides=slots.pack_overrides(
                config, emu_profiles, db, held_zip_contents, data_registry,
                target_cores=target_cores, source=source,
            ) if db is not None else None,
        )
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions, held
        )

    with zipfile.ZipFile(zip_path, "r") as zf:
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

        errors.extend(_structural_errors(zf, zip_set))

        # 1. Baseline file presence + native hash check
        verification_mode = config.get("verification_mode", "existence")
        baseline_checked = 0
        baseline_present = 0
        baseline_excluded = 0
        baseline_absent = 0
        decl_by_member: dict[str, list[dict]] = {}
        # Mirror the builder's path-conflict logic: a declaration whose path
        # collides file-vs-directory with a packed member was skipped by the
        # builder (upstream declares e.g. both SGB1.sfc and SGB1.sfc/program.rom)
        zip_parents: set[str] = set()
        for n in zip_set:
            parts = n.split("/")
            for i in range(1, len(parts)):
                zip_parents.add("/".join(parts[:i]))
        baseline_groups: dict[str, list[dict]] = {}
        system_of: dict[int, str] = {}
        for sys_id, system in (expected_systems if source != "truth" else {}).items():
            for fe in system.get("files", []):
                system_of[id(fe)] = sys_id
                if required_only and fe.get("required") is False:
                    continue
                dest = sanitize_pack_path(fe.get("destination", fe.get("name", "")))
                if not dest:
                    continue
                if region_drops and dest in region_drops:
                    continue
                expected = f"{base_dest}/{dest}" if base_dest and not is_flat else dest
                baseline_groups.setdefault(expected, []).append(fe)

        baseline_checked = len(baseline_groups)
        # RetroBat's group: one packed file of it is enough, as verify counts it.
        packed_groups = {
            (system_of[id(fe)], fe["group"])
            for expected, declarations in baseline_groups.items()
            if expected in zip_set or expected.lower() in zip_lower
            for fe in declarations
            if fe.get("group")
        }
        exclusion_index = build_zip_contents_index(db) if db is not None else {}
        categories = EntryCategories(config, emu_profiles, data_registry)
        for expected, declarations in baseline_groups.items():
            if expected in zip_set:
                member = expected
            elif expected.lower() in zip_lower:
                member = zip_lower[expected.lower()]
            elif _has_path_conflict(expected, zip_set, zip_parents):
                # Skipped by the builder for the same reason: not an error
                baseline_present += 1
                continue
            elif db is not None and _intentional_hash_exclusion(
                declarations,
                db,
                zip_contents=exclusion_index,
                data_dir_registry=data_registry,
                verification_mode=verification_mode,
                hash_rule=config.get("hash_rule", ""),
            ):
                baseline_excluded += 1
                continue
            elif all(
                fe.get("group") and (system_of[id(fe)], fe["group"]) in packed_groups
                for fe in declarations
            ):
                baseline_absent += 1
                continue
            elif db is not None and all(
                categories.category(fe, fe.get("destination", fe.get("name", "")),
                                    system_of[id(fe)]) != BIOS
                for fe in declarations
            ) and _held_nowhere(declarations, db, exclusion_index, data_registry):
                # A game's data or an entry no core opens that the collection
                # lacks: verify counts it apart. Missing firmware stays an error.
                baseline_absent += 1
                continue
            else:
                errors.append(f"baseline missing: {expected}")
                continue
            baseline_present += 1
            decl_by_member.setdefault(member, []).extend(declarations)

        # Reproduce the platform's native hash check on pack bytes.
        # A destination declared by several entries passes when the packed
        # member satisfies any of them. A failure only counts as a pack
        # error when the repo holds a file matching a declaration: without
        # one, the pack ships its best effort and the gap is a data issue
        # reported by verify.py, not a generation bug.
        digest = digest_algorithm(verification_mode)
        hash_rule = config.get("hash_rule", "")
        if reads_file_contents(verification_mode) and digest:
            for member, decl_entries in decl_by_member.items():
                checkable = [
                    fe
                    for fe in decl_entries
                    if str(fe.get(digest) or "").strip()
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

        # 2. Core extras: the builder's own placement replayed
        #    (packextras.hidden_extras, which verify reads too), after the
        #    platform files it wrote. Each placed extra must sit at its path
        #    with the bytes the builder resolved: an empty seen set and a
        #    presence test credited a core file at a path where the pack
        #    holds the platform's other dump.
        core_checked = 0
        core_present = 0
        if db is not None and source != "platform":
            placed_local = _builder_extras(
                config, emulators_dir, db, emu_profiles, baseline_groups,
                base_dest, is_flat, zip_set, zip_lower, target_cores,
                region_drops, data_registry,
                include_all=(source == "truth"), required_only=required_only,
            )
            for full, local in sorted(placed_local.items()):
                core_checked += 1
                member = _flat(full, base_dest, is_flat)
                member = member if member in zip_set else zip_lower.get(member.lower())
                if member is None:
                    errors.append(f"core missing: {full}")
                elif not _same_content(zf, member, local):
                    errors.append(
                        f"core file differs: {member} is not the {os.path.basename(local)}"
                        " the builder places there"
                    )
                else:
                    core_present += 1

        checked = baseline_checked + core_checked
        present = baseline_present + core_present

    return (
        len(errors) == 0,
        checked,
        present,
        errors,
        baseline_checked,
        baseline_present,
        core_checked,
        core_present,
        baseline_excluded,
        baseline_absent,
    )
