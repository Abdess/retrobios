"""Whether a pack's copy passes the hash check its platform runs natively."""

from __future__ import annotations

import io
import os
import zipfile

from core.hashing import md5_composite, md5_composite_of, parse_hash_list, stream_hashes
from core.ziptools import is_archive_path
from resolve.lookup import held_record_for
from resolve.nativemode import digest_algorithm, platform_mode, reads_file_contents
from resolve.acceptance import digest_verdict, inner_rom_check, inner_rom_data_check


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

    unreadable: list[Exception] = []

    def composite() -> str | None:
        # Recalbox's Md5Composite, over the sorted members of a ZIP.
        if not member.endswith(".zip"):
            return None
        try:
            return md5_composite_of(io.BytesIO(zf.read(member)))
        except (zipfile.BadZipFile, OSError) as exc:
            unreadable.append(exc)
            return None

    if digest_verdict(
        file_entry, zf.getinfo(member).file_size, lambda: computed, mode, rule, composite
    ):
        return None
    # Only a composite-only entry has the member digest as its one answer:
    # elsewhere the container md5 is the comparison that failed.
    if unreadable and file_entry.get("zip_digest") == "composite":
        return f"{member}: unreadable nested archive ({unreadable[0]})"
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


def native_hash_errors(
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
