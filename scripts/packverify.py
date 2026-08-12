"""Checking a built pack the way the frontend would.

The builder and the verifier have to reach the same verdict on the
same file, so both read the native mode from one place: a pack and a
coverage report that disagree describe different collections."""

from __future__ import annotations

from auto_fetch import DEFAULT_BIOS_DIR
from artifacts import _build_timestamp
from packextras import _collect_emulator_extras
from packextras import _detect_extras_prefix
from packpaths import _has_path_conflict
from packpaths import _register_path
from ziptools import build_zip_contents_index
from ziptools import check_inside_zip
from nativemode import digest_algorithm
from nativemode import hash_mismatch_excludes_file
import hashlib
from common import load_emulator_profiles
from common import load_platform_config
import os
from packextras import platform_region_groups
from nativemode import reads_file_contents
import region as region_mod
from packresolve import resolve_file
from common import sanitize_pack_path
import zipfile
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
            if name.startswith("INSTRUCTIONS_") or name in (
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
                    try:
                        import io as _io

                        with zipfile.ZipFile(_src_path) as _sz:
                            _sc = {
                                i.filename: i.CRC
                                for i in _sz.infolist()
                                if not i.is_dir()
                            }
                        with zipfile.ZipFile(_io.BytesIO(zf.read(name))) as _pz:
                            _pc = {
                                i.filename: i.CRC
                                for i in _pz.infolist()
                                if not i.is_dir()
                            }
                        if _sc == _pc:
                            status = "verified_rebuild"
                            file_name = _bn
                            break
                    except (zipfile.BadZipFile, OSError):
                        continue

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
                    if os.path.getsize(_dp) == size:
                        status = "verified_data"
                        file_name = _bn
                        break
                    if name.endswith(".zip") and _dp.endswith(".zip"):
                        try:
                            import io as _io2

                            with zipfile.ZipFile(_io2.BytesIO(zf.read(name))) as _pz2:
                                _pc2 = {
                                    i.filename: i.CRC
                                    for i in _pz2.infolist()
                                    if not i.is_dir()
                                }
                            with zipfile.ZipFile(_dp) as _dz:
                                _dc = {
                                    i.filename: i.CRC
                                    for i in _dz.infolist()
                                    if not i.is_dir()
                                }
                            if _pc2 == _dc:
                                status = "verified_data"
                                file_name = _bn
                                break
                        except (zipfile.BadZipFile, OSError):
                            continue

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
    and truncated MD5s (Batocera 29-char): a declared value shorter
    than the digest matches by prefix.
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
    zf: zipfile.ZipFile, member: str, file_entry: dict, mode: str
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

    h = hashlib.md5() if mode == "md5" else hashlib.sha1()
    with zf.open(member) as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if _hash_matches(declared, actual):
        return None

    # Recalbox Md5Composite: MD5 over sorted inner contents of a ZIP,
    # independent of compression and metadata (Zip::Md5Composite()).
    if mode == "md5" and member.endswith(".zip"):
        import io

        try:
            with zipfile.ZipFile(io.BytesIO(zf.read(member))) as inner:
                names = sorted(n for n in inner.namelist() if not n.endswith("/"))
                ch = hashlib.md5()
                for n in names:
                    ch.update(inner.read(n))
            if _hash_matches(declared, ch.hexdigest()):
                return None
        except (zipfile.BadZipFile, OSError):
            pass

    return f"{member}: {mode} {actual} != declared {declared}"

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

def _intentional_hash_exclusion(
    entries: list[dict],
    db: dict,
    bios_dir: str = DEFAULT_BIOS_DIR,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
    verification_mode: str = "md5",
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
        if status != "hash_mismatch":
            return False

        # A container can mismatch the outer declaration while still carrying
        # the exact inner ROM requested by Batocera-style zipped_file entries.
        zipped_file = entry.get("zipped_file")
        if zipped_file and local_path:
            declared = str(entry.get("md5") or "")
            candidates = [value.strip() for value in declared.split(",") if value.strip()]
            if not candidates:
                candidates = [""]
            if any(
                check_inside_zip(local_path, zipped_file, candidate) == "ok"
                for candidate in candidates
            ):
                return False
    return True

def verify_pack_against_platform(
    zip_path: str,
    platform_name: str,
    platforms_dir: str,
    db: dict | None = None,
    emulators_dir: str = "emulators",
    emu_profiles: dict | None = None,
    regions: list[str] | None = None,
    data_registry: dict | None = None,
) -> tuple[bool, int, int, list[str], int, int, int, int, int]:
    """Verify a pack ZIP against its platform config and core requirements.

    A region priority list narrows the expectation to what the builder would
    have packed, using the same selection function.

    Checks:
    1. Every baseline file declared by the platform exists in the ZIP
       at the correct destination path
    2. Every in-repo core extra file (from emulator profiles) is present
    3. No duplicate entries
    4. No path anomalies (double slash, absolute, traversal)
    5. No unexpected zero-byte BIOS files

    Returns ``(all_ok, checked, present, errors, baseline_checked,
    baseline_present, core_checked, core_present, baseline_excluded)``.
    """
    from collections import Counter

    config = load_platform_config(platform_name, platforms_dir)
    base_dest = config.get("base_destination", "")
    errors: list[str] = []
    checked = 0
    present = 0

    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)

    region_drops: set[str] = set()
    if regions:
        region_index = region_mod.build_region_index(emu_profiles)
        region_groups, _extra_dests = platform_region_groups(
            config,
            config.get("systems", {}),
            emulators_dir,
            db,
            base_dest,
            emu_profiles,
        )
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions
        )

    with zipfile.ZipFile(zip_path, "r") as zf:
        zip_set = set(zf.namelist())
        zip_lower = {n.lower(): n for n in zip_set}

        # Auto-detect flat vs nested ZIP
        is_flat = bool(base_dest) and not any(
            n.startswith(base_dest + "/")
            for n in zip_set
            if n not in ("README.txt", "manifest.json") and not n.endswith("/")
        )

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
                ):
                    errors.append(f"zero-byte: {info.filename}")

        # 1. Baseline file presence + native hash check
        verification_mode = config.get("verification_mode", "existence")
        baseline_checked = 0
        baseline_present = 0
        baseline_excluded = 0
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
        for _sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                dest = sanitize_pack_path(fe.get("destination", fe.get("name", "")))
                if not dest:
                    continue
                if region_drops and dest in region_drops:
                    continue
                expected = f"{base_dest}/{dest}" if base_dest and not is_flat else dest
                baseline_groups.setdefault(expected, []).append(fe)

        baseline_checked = len(baseline_groups)
        exclusion_index = build_zip_contents_index(db) if db is not None else {}
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
            ):
                baseline_excluded += 1
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
        if reads_file_contents(verification_mode) and digest:
            for member, decl_entries in decl_by_member.items():
                checkable = [
                    fe
                    for fe in decl_entries
                    if str(fe.get(digest) or "").strip()
                ]
                if not checkable:
                    continue
                member_errors = []
                satisfied = False
                for fe in checkable:
                    err = _check_member_hash(zf, member, fe, digest)
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

        # 2. Core extras presence (files from emulator profiles, in repo)
        #    Mirror the pack builder's skip logic: only count files that
        #    can actually be resolved and don't have path conflicts.
        core_checked = 0
        core_present = 0
        if db is not None:
            core_files = _collect_emulator_extras(
                config,
                emulators_dir,
                db,
                set(),
                base_dest,
                emu_profiles,
            )
            seen_conformance: set[str] = set(zip_set)
            seen_parents: set[str] = set()
            for n in zip_set:
                parts = n.split("/")
                for i in range(1, len(parts)):
                    seen_parents.add("/".join(parts[:i]))
            extras_pfx = _detect_extras_prefix(config, base_dest)
            for fe in core_files:
                raw_dest = fe.get("destination", fe.get("name", ""))
                dest = sanitize_pack_path(raw_dest)
                if not dest:
                    continue
                if region_drops and sanitize_pack_path(dest) in region_drops:
                    continue
                if extras_pfx and not (is_flat and extras_pfx == base_dest):
                    if not dest.startswith(f"{extras_pfx}/"):
                        full = f"{extras_pfx}/{dest}"
                    else:
                        full = dest
                else:
                    full = dest
                # Skip path conflicts (same logic as pack builder)
                if _has_path_conflict(full, seen_conformance, seen_parents):
                    continue
                # Skip unresolvable files (game_data dirs, etc.)
                local_path, status = resolve_file(
                    fe,
                    db,
                    "bios",
                    {},
                    dest_hint=raw_dest,
                    data_dir_registry=data_registry,
                    offline=True,
                )
                if status in ("not_found", "external", "user_provided"):
                    continue
                core_checked += 1
                if full in zip_set or full.lower() in zip_lower:
                    core_present += 1
                    seen_conformance.add(full)
                    _register_path(full, seen_conformance, seen_parents)
                else:
                    errors.append(f"core missing: {full}")

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
    )
