"""Reviewing a contributed file: whether the collection knows it, accepts it, and where in bios/ it goes."""

from __future__ import annotations

import os
import urllib.parse
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict

try:
    import yaml
except ImportError:
    yaml = None

from core.hashing import compute_hashes, stream_hashes
from core.memo import DerivedView
from model.nodedup import in_nodedup_dir
from resolve.nativemode import digest_algorithm
from resolve.acceptance import frontend_digest_matches, inner_rom_check

if TYPE_CHECKING:
    from typing_extensions import Unpack
from resolve.reviewhashes import name_systems


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


def large_file_issue_url(result: ValidationResult) -> str:
    """The issue form with the values this run computed already filled in.

    GitHub fills an issue form field from the query parameter named by its
    id: filename, sha1, md5 and size in missing-bios.yml.
    """
    fields = {
        "title": f"[BIOS] Missing: {result.filename}",
        "filename": result.filename,
        "sha1": result.sha1,
        "md5": result.md5,
        "size": str(result.size),
    }
    return f"{LARGE_FILE_ISSUE_URL}&{urllib.parse.urlencode(fields)}"


class ValidationResult:
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.checks: list[tuple[str, str]] = []  # (status, message) tuples
        self.sha1 = ""
        self.md5 = ""
        self.crc32 = ""
        self.size = 0
        # "held" (a copy of a file the collection has) or "unknown" (no list
        # or profile declares it): no check fails, and neither is a file
        # the pull request adds to the collection.
        self.outcome = ""
        # Where --place copies the file: one folder and one declared name, or
        # the .variants/ slot of a name the collection already holds.
        self.destination = ""

    def add_check(self, passed: bool, message: str) -> None:
        self.checks.append(("PASS" if passed else "FAIL", message))

    def add_warning(self, message: str) -> None:
        self.checks.append(("WARN", message))

    def add_info(self, message: str) -> None:
        self.checks.append(("INFO", message))

    @property
    def passed(self) -> bool:
        return all(s != "FAIL" for s, _ in self.checks)

    @property
    def status(self) -> str:
        return "FAIL" if not self.passed else "REVIEW" if self.outcome else "PASS"


@dataclass(frozen=True)
class _Digests:
    """The digests of one file or ZIP member, as the hash tables key them."""

    sha1: str
    md5: str
    sha256: str
    crc32: str
    size: int


@dataclass(frozen=True)
class _DigestMatch:
    """Which declaration a file's digests match: a platform's sha1, md5, other hash, a profile."""

    sha1: bool
    md5: bool
    other: bool
    by_profile: set[str] | None

    @property
    def any(self) -> bool:
        return bool(self.sha1 or self.md5 or self.other or self.by_profile)


def _known_digest(
    digests: _Digests, platform_hashes: dict, profile_hashes: dict
) -> _DigestMatch:
    """The one rule that knows a file by its bytes, loose or inside a ZIP."""
    crc32 = profile_hashes.get("crc32", {})
    return _DigestMatch(
        sha1=digests.sha1 in platform_hashes.get("sha1", set()),
        md5=digests.md5 in platform_hashes.get("md5", set()),
        other=(
            digests.sha256 in platform_hashes.get("sha256", set())
            or (digests.crc32, digests.size) in platform_hashes.get("crc32", set())
        ),
        by_profile=(
            profile_hashes.get("sha1", {}).get(digests.sha1)
            or profile_hashes.get("sha256", {}).get(digests.sha256)
            or profile_hashes.get("md5", {}).get(digests.md5)
            or crc32.get((digests.crc32, digests.size))
            or crc32.get((digests.crc32, None))
        ),
    )


def _archive_members(
    filepath: str, db: dict | None, platform_hashes: dict, profile_hashes: dict
) -> list[str] | None:
    """What each file of a ZIP is, None when filepath is not a ZIP.

    Read only for an archive no list declares as a whole: MAME and FBNeo
    sets are ZIP BIOS files in their own right.
    """
    if not zipfile.is_zipfile(filepath):
        return None
    held = (db or {}).get("files", {})
    described = []
    try:
        with zipfile.ZipFile(filepath) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_FILE_SIZE:
                    described.append(f"`{info.filename}` too large to read here")
                    continue
                with archive.open(info) as handle:
                    digests = stream_hashes(handle, frozenset({"sha1", "md5", "sha256"}))
                sha1_hex = digests["sha1"]
                if sha1_hex in held:
                    state = f"already held at `{held[sha1_hex]['path']}`"
                elif _known_digest(
                    _Digests(sha1_hex, digests["md5"], digests["sha256"],
                             f"{info.CRC:08x}", info.file_size),
                    platform_hashes, profile_hashes,
                ).any:
                    state = "declared and not held"
                else:
                    state = "not recognised"
                described.append(f"`{info.filename}` {state}")
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        # An encrypted member raises RuntimeError.
        described.append(f"unreadable ({exc})")
    return described


@dataclass(frozen=True)
class _Review:
    """One file under review and the tables it is read against."""

    filepath: str
    db: dict | None
    platform_hashes: dict
    profile_hashes: dict


@dataclass(frozen=True)
class _Known:
    """What declares the file: a platform's hash, its own check, a profile, its name."""

    sha1: bool
    md5: bool
    other: bool
    accepted_by: set[str]
    by_profile: set[str] | None
    name: bool

    @property
    def by_platform(self) -> bool:
        return bool(self.sha1 or self.md5 or self.other or self.accepted_by)


def _path_problem(filepath: str) -> str:
    """Why the path cannot be reviewed, empty when it can."""
    # Whoever opened the pull request chose this path, so its shape is
    # settled before anything is read. A symlink to an endless device would
    # otherwise be hashed until the job timed out, and a symlink out of the
    # checkout would be reported as though its target had been contributed.
    if os.path.islink(filepath):
        return "Symlinks are not allowed"
    if not os.path.exists(filepath):
        return (f"File not found: {filepath}. A path is read from the folder "
                "the command runs in, or pass --changed to check the files "
                "changed under bios/")
    if os.path.isdir(filepath):
        return "Folder with no file in it"
    if not os.path.isfile(filepath):
        return "Not a regular file: a device, a pipe or a socket"
    return ""


def _check_size(result: ValidationResult) -> bool:
    """The size checks, True when the file is too large for git."""
    too_large = result.size > MAX_FILE_SIZE
    if too_large:
        # GitHub refuses a pushed file over 100 MiB, so a pull request cannot
        # carry it. Only a maintainer can add an asset to the release.
        result.add_check(
            False,
            f"File too large for git ({result.size:,} > {MAX_FILE_SIZE:,} bytes). "
            "Leave it out of the pull request and open an issue, its hashes "
            f"filled in ({large_file_issue_url(result)}), saying where the file "
            "can be obtained: a maintainer adds it to the `large-files` release.",
        )
    elif result.size == 0:
        result.add_check(False, "File is empty (0 bytes)")
    else:
        result.add_check(True, f"File size within limits ({result.size:,} bytes)")
    return too_large


def _relative_path(filepath: str) -> str:
    # Paths are compared as the database writes them, relative to the
    # checkout: an absolute path to the file itself read as its duplicate.
    if os.path.isabs(filepath):
        candidate = os.path.relpath(filepath, os.getcwd())
        if not candidate.startswith(".."):
            return candidate
    return filepath


def _check_duplicate(result: ValidationResult, db: dict, relative: str) -> None:
    if result.sha1 not in db.get("files", {}):
        result.add_check(True, "Not a duplicate in database")
        return
    existing = db["files"][result.sha1]
    held_at = existing.get("path")
    if held_at and os.path.normpath(relative) == os.path.normpath(held_at):
        # The file the database was built from, not a copy of it: a
        # PR that regenerated database.json was told each new file
        # duplicated itself.
        result.add_check(True, "Already in the database at this path")
    elif in_nodedup_dir(relative):
        result.add_info(
            f"Identical to `{existing['path']}`, kept: this tree is read by path"
        )
    else:
        result.outcome = "held"
        result.add_warning(
            f"Already held at `{existing['path']}`: nothing to add, "
            "leave this copy out of the pull request"
        )


def _identify(review: _Review, result: ValidationResult, sha256: str) -> _Known:
    platform_hashes = review.platform_hashes
    match = _known_digest(
        _Digests(result.sha1, result.md5, sha256, result.crc32, result.size),
        platform_hashes, review.profile_hashes,
    )
    accepted_by = (
        set() if match.sha1 or match.md5 or match.other
        else _platforms_accepting(review.filepath, result.filename, platform_hashes)
    )
    return _Known(match.sha1, match.md5, match.other, accepted_by, match.by_profile,
                  result.filename in platform_hashes.get("names", set()))


def _check_executable(result: ValidationResult, sha256: str, profile_hashes: dict, ext: str) -> None:
    # An executable is refused unless an emulator profile pins its exact
    # bytes: PICO-8's pico8.exe and SDL2.dll are declared by sha1 from the
    # official archive. A weak hash (md5, crc32) never vouches for code.
    pinned = (
        profile_hashes.get("sha1", {}).get(result.sha1)
        or profile_hashes.get("sha256", {}).get(sha256)
    )
    if pinned:
        result.add_check(
            True,
            f"Executable whose bytes an emulator profile pins by sha1: {', '.join(sorted(pinned))}",
        )
    else:
        result.add_check(False, f"Blocked file extension: {ext}")


def _check_known(review: _Review, result: ValidationResult, known: _Known, too_large: bool) -> list[str] | None:
    """What declares the file, and the files of a ZIP no list declares
    whole, when the upload is one."""
    if known.sha1:
        result.add_check(True, "SHA1 matches known platform requirement")
    elif known.md5:
        result.add_check(True, "MD5 matches known platform requirement")
    elif known.other:
        result.add_check(True, "Hash matches known platform requirement")
    elif known.accepted_by:
        result.add_check(
            True, "Accepted by the platform's own check: " + ", ".join(sorted(known.accepted_by))
        )
    elif known.by_profile:
        names = sorted(known.by_profile)
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        result.add_check(True, f"Hash matches a file the emulator profile declares: {shown}")
    elif known.name:
        result.add_warning(
            "Filename matches a known requirement but hash differs - may be a variant"
        )
    else:
        result.outcome = "unknown"
        members = None if too_large else _archive_members(
            review.filepath, review.db, review.platform_hashes, review.profile_hashes
        )
        _report_unknown(result, members, too_large)
        return members
    return None


def _report_unknown(result: ValidationResult, members: list[str] | None, too_large: bool) -> None:
    if members is not None:
        # A folder zipped to upload many files at once was hashed as one
        # file and its contributor asked where that dump came from.
        shown = "; ".join(members[:10]) + (
            f"; and {len(members) - 10} more" if len(members) > 10 else ""
        )
        result.add_warning(
            "A ZIP no platform list or emulator profile declares as a whole: "
            "add the files it holds, unzipped, not the archive. Inside: "
            + (shown or "nothing")
        )
    else:
        result.add_warning(
            "Not recognised: no platform list or emulator profile declares this "
            f"file. Say in the {'issue' if too_large else 'pull request'} which "
            "emulator reads it, for which system, and where the dump comes from"
        )


def _check_bios_placement(result: ValidationResult, normalized: str, expected: list[str]) -> None:
    parts = normalized.split(os.sep)
    here = f"bios/{parts[1]}/{parts[2]}/" if len(parts) >= 4 else ""
    makers = {folder.split("/")[1] for folder in expected}
    if expected and (len(parts) < 4 or parts[1] not in makers):
        # Depth alone passed a PS1 BIOS filed under bios/Nintendo/Game Boy/.
        result.add_warning(
            "Placed under " + (here or "the bios/ root") + ", while the other files of "
            "its system are in " + " or ".join(f"`{f}`" for f in expected)
        )
    elif len(parts) >= 4:
        result.add_check(True, f"Correct placement: bios/{parts[1]}/{parts[2]}/")
    else:
        result.add_warning("File should be in bios/Manufacturer/Console/ structure")


def _suggest_destination(review: _Review, result: ValidationResult, values: tuple[str, ...],
                         known: _Known) -> None:
    # The contributor asks before forking: say where it goes.
    spot = placement(
        values, result.filename, review.db, review.platform_hashes, review.profile_hashes,
        declared=bool(known.by_platform or known.by_profile),
    )
    result.destination = spot.destination(result.md5)
    copies = f". --place copies it to `{result.destination}`" if result.destination else ""
    if spot.folders:
        result.add_warning(
            "File is not under bios/ yet. Its system's files are in "
            + " or ".join(f"`{f}`" for f in spot.folders) + copies
        )
    elif spot.home:
        result.add_warning(
            f"File is not under bios/ yet. The collection keeps this name in `{spot.home}`"
            + copies
        )
    else:
        result.add_warning(
            "File is not under bios/ yet. Place it in bios/Manufacturer/Console/"
        )


def _check_declared_size(result: ValidationResult, platform_hashes: dict, profile_hashes: dict) -> bool:
    """True when the size fits every declaration of the name."""
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
    return size_fits


def _note_variant(review: _Review, result: ValidationResult, normalized: str) -> None:
    platform_hashes, profile_hashes = review.platform_hashes, review.profile_hashes
    owners = name_systems(result.filename, platform_hashes, profile_hashes)
    home = _variant_home(review.db, result.filename, "", set() if len(owners) > 1 else {
        d for table in (platform_hashes, profile_hashes) for s in owners
        for d in table.get("system_dirs", {}).get(s, ())
    } if owners else None)
    if not home and normalized.startswith("bios" + os.sep):
        # Beside the file, in the folder the contributor chose.
        home = os.path.dirname(normalized).replace(os.sep, "/") + "/"
    slot = f"{home}.variants/{result.filename}.{result.md5[:8]}"
    if home and not normalized.startswith("bios" + os.sep):
        result.destination = slot
    if home:
        result.add_info(
            f"This may be a valid variant. If accepted, it will be placed in `{slot}`"
        )
    else:
        result.add_info("This may be a valid variant of a file the collection lacks")


def validate_file(
    filepath: str,
    db: dict | None,
    platform_hashes: dict,
    profile_hashes: dict | None = None,
) -> ValidationResult:
    """Run all validation checks on a file."""
    result = ValidationResult(filepath)
    problem = _path_problem(filepath)
    if problem:
        result.add_check(False, problem)
        return result

    result.size = os.path.getsize(filepath)
    hashes = compute_hashes(filepath)
    result.sha1 = hashes["sha1"]
    result.md5 = hashes["md5"]
    result.crc32 = hashes["crc32"]
    sha256 = hashes.get("sha256", "")

    ext = os.path.splitext(filepath)[1].lower()
    too_large = _check_size(result)
    relative = _relative_path(filepath)
    if db:
        _check_duplicate(result, db, relative)

    review = _Review(filepath, db, platform_hashes, profile_hashes or {})
    known = _identify(review, result, sha256)
    if ext in BLOCKED_EXTENSIONS:
        _check_executable(result, sha256, review.profile_hashes, ext)
    members = _check_known(review, result, known, too_large)

    normalized = os.path.normpath(relative)
    values = (result.sha1, result.md5, sha256)
    if too_large:
        # The file stays out of the pull request, so no folder of bios/ is
        # the contributor's to choose: the release asset is placed by hand.
        pass
    elif normalized.startswith("bios" + os.sep):
        _check_bios_placement(result, normalized,
                              expected_folders(values, platform_hashes, review.profile_hashes))
    elif result.outcome == "held" or members is not None:
        # Nothing to place: a copy, or an archive whose files go in unzipped.
        pass
    else:
        _suggest_destination(review, result, values, known)

    size_fits = _check_declared_size(result, platform_hashes, review.profile_hashes)
    if known.name and not known.by_platform and not known.by_profile and size_fits:
        _note_variant(review, result, normalized)
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


def expected_folders(
    values: Iterable[str], platform_hashes: dict, profile_hashes: dict | None
) -> list[str]:
    """The bios/<Manufacturer>/<Console>/ folders the files of a hash's
    system are in, read from the first of *values* a table knows.

    A platform's declaration first, then a profile's: most files the gaps
    page lists are declared by a profile alone.
    """
    for table in (platform_hashes, profile_hashes or {}):
        for value in values:
            if value and value in table.get("folders", {}):
                return sorted(table["folders"][value])
    return []


@dataclass(frozen=True)
class Placement:
    """Where a file not under bios/ yet goes.

    ``folders`` are those of its system, ``home`` the folder the collection
    keeps its name in when its system names none. ``name`` is the name it
    is copied under, empty when the declarations do not settle one.
    ``variant`` says a file of that name is already in the folder: a copy
    goes beside it in .variants/, never over it.
    """

    folders: tuple[str, ...] = ()
    home: str = ""
    name: str = ""
    variant: bool = False

    @property
    def folder(self) -> str:
        return self.folders[0] if self.folders else self.home

    def destination(self, md5: str) -> str:
        """The path it is copied to, a variant tagged with its md5 prefix."""
        if not self.name:
            return ""
        if self.variant:
            return f"{self.folder}.variants/{self.name}.{md5[:8]}"
        return self.folder + self.name


class PlacementOptions(TypedDict, total=False):
    """How placement() tests a path, and the systems and directory a
    declaration names."""

    exists: Callable[[str], bool]
    systems: Iterable[str]
    directory: str


def placement(
    values: Iterable[str],
    filename: str,
    db: dict | None,
    platform_hashes: dict,
    profile_hashes: dict | None,
    *,
    declared: bool,
    **options: Unpack[PlacementOptions],
) -> Placement:
    """Where a file goes, by its hashes and its name.

    The review and the site's wanted page both read this one rule, so the
    folder a contributor is sent to is the folder the review accepts.
    *declared* says a list or a profile declares one of the hashes: a file
    known by its name alone gets a slot only once its size fits.

    Without a folder from its hashes, the folder comes from its system:
    *systems*, or every system that declares the name (several of them
    name no copy to sit beside). A file of that name held elsewhere is a
    homonym and says nothing: AmberELEC's MSX config.ini
    was sent beside msx.emu's ColecoVision config.ini. A declared
    *directory* (Machines/MSX2/ for one machine's config.ini) narrows it: a
    copy by name counts only in a directory of that tail, and a held
    directory of that tail is the folder.
    """
    exists = options.get("exists", os.path.exists)
    systems = options.get("systems", ())
    directory = options.get("directory", "")
    values = [value for value in values if value]
    folders = expected_folders(values, platform_hashes, profile_hashes)
    if folders:
        names = {
            name
            for table in (platform_hashes, profile_hashes or {})
            for value in values
            for name in table.get("named", {}).get(value, ())
        }
        name = next(iter(names)) if len(names) == 1 else ""
        if len(folders) == 1 and name and "/" not in name:
            return Placement(tuple(folders), name=name, variant=exists(folders[0] + name))
        return Placement(tuple(folders))
    held = next((value for value in values if value in (db or {}).get("files", {})), "")
    owners = set(systems) or name_systems(filename, platform_hashes, profile_hashes)
    tables = (platform_hashes, profile_hashes or {})
    # A name several systems declare does not say which one a file is:
    # a copy held for one of them is no answer.
    dirs: set[str] = set() if not systems and len(owners) > 1 else {
        d for table in tables for s in owners for d in table.get("system_dirs", {}).get(s, ())
    }
    tail = _directory_tail(db, directory)
    within: set[str] | None = dirs
    if tail:
        within = {d for d in dirs if d.endswith("/" + tail) or d == tail} if owners else None
    home = _variant_home(db, filename, held, within if owners or tail else None)
    if declared and home and filename and "/" not in filename:
        # The folder holds a file of that name already.
        return Placement(home=home, name=filename, variant=True)
    if home:
        return Placement(home=home)
    if tail:
        return Placement(home=next(d for d in _held_directories(db) if d.endswith("/" + tail) or d == tail))
    homes = {f for table in tables for s in owners for f in table.get("system_folders", {}).get(s, ())}
    return Placement(tuple(sorted(homes)))


def _directories_of(files: dict) -> frozenset[str]:
    return frozenset(
        path.rsplit("/", 1)[0] + "/"
        for record in files.values()
        if "/" in (path := record.get("path") or "") and "/.variants/" not in path
    )


_held_view = DerivedView(_directories_of)


def _held_directories(db: dict | None) -> frozenset[str]:
    """Every directory a file of the database sits in, .variants/ aside."""
    return _held_view((db or {}).get("files", {}))


def _directory_tail(db: dict | None, directory: str) -> str:
    """The longest tail of a declared directory, two segments at least,
    that exactly one held directory ends with, empty when none does."""
    parts = [p for p in directory.strip("/").split("/") if p]
    held = _held_directories(db)
    for size in range(len(parts), 1, -1):
        tail = "/".join(parts[-size:]) + "/"
        found = [d for d in held if d.endswith("/" + tail) or d == tail]
        if len(found) == 1:
            return tail
        if found:
            return ""
    return ""


def _variant_home(db: dict | None, name: str, held: str = "",
                  within: set[str] | None = None) -> str:
    """The folder the collection keeps a name in, for its variants beside it.

    The folder of an identical copy comes first: adam_fdc.zip, held in
    bios/Coleco/Adam/, was sent to bios/Arcade/MAME/, the first folder
    the name index gave. A copy found by name alone counts only in a
    directory of *within*, those the file's own systems are held in, when
    the systems are known.
    """
    files = (db or {}).get("files", {})
    by_name = (db or {}).get("indexes", {}).get("by_name", {}).get(name, [])
    copies = [(held, True)] if held in files else []
    for sha1, identical in copies + [(sha1, False) for sha1 in by_name]:
        path = str(files.get(sha1, {}).get("path", ""))
        folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
        if not folder or "/.variants" in "/" + folder:
            continue
        if identical or within is None or folder in within:
            return folder
    return ""
