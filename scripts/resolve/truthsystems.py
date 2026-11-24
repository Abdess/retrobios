"""The platform side of a truth: its entries by system, the system map, and how two declarations compare."""

from __future__ import annotations

from dataclasses import dataclass

from core.hashing import HASH_FIELDS, declared_hashes, lists_hashes
from model.database import record_for_hash
from model.declarations import OUTER_ROOTS
from model.systems import norm_system_id
from resolve.entryscope import (
    filter_files_by_mode,
    installed_with_emulator,
    opens_by_name,
    read_from_system_dir,
    unread_on,
)
from resolve.launches import PlatformLaunches
from resolve.standalone import platform_layouts


def enrich_hashes(entry: dict, db: dict) -> None:
    """Fill the hashes a profile omits from the record its own hash names.

    The record is found by sha1, sha256, then md5, then crc32 with the size
    when the profile gives one. Never by name: a file in bios/ under the same
    name may not be the bytes the source code expects. An entry listing
    several accepted values for a hash is left as is.
    """
    if any(isinstance(entry.get(h), list) for h in HASH_FIELDS):
        return

    files_db = db.get("files", {})
    record = None
    # rust_dos names its SC-55 ROMs by sha256 alone, ares 5200.rom too.
    for kind in ("sha1", "sha256", "md5"):
        sha1 = record_for_hash(db, kind, entry.get(kind))
        if sha1:
            record = files_db[sha1]
            break

    # CRC32 (32-bit, collisions theoretically possible): the size must
    # match when the profile has one.
    if record is None:
        sha1 = record_for_hash(db, "crc32", entry.get("crc32"))
        candidate = files_db[sha1] if sha1 else None
        if candidate is not None:
            profile_size = entry.get("size")
            if not profile_size or candidate.get("size") == profile_size:
                record = candidate

    if record is None:
        return

    # Copy sibling hashes and size from the anchored record.
    for field in ("sha1", "md5", "sha256", "crc32"):
        if not entry.get(field) and record.get(field):
            entry[field] = record[field]
    if not entry.get("size") and record.get("size"):
        entry["size"] = record["size"]


def require_by_slot(files: list[dict]) -> None:
    """A core that requires a name an entry answers for requires the entry.

    Merged by name, one core's alternatives land in several entries. Ymir
    reads sega_101.bin, mpr-17933.bin or saturn_bios.bin, so the sega_101.bin
    entry carries those aliases. kronos, yabause and yabasanshiro open
    saturn_bios.bin first and sega_101.bin as a fallback: they sat in that
    entry's _cores, out of its _required_by, while their saturn_bios.bin entry
    had them requiring it, and a platform line paired through the alias read
    them as optional. A core already among the entry's readers that requires
    one of its aliases, as another entry of the system, is one of its
    requirers. No reader is added.
    """
    required_by_name: dict[str, set[str]] = {}
    for entry in files:
        required_by_name.setdefault(entry["name"].lower(), set()).update(
            entry.get("_required_by", ())
        )
    for entry in files:
        # Only the aliases: entries sharing the entry's own name are other
        # files that name already kept apart (pak0.pak under each game).
        names = {str(alias).lower() for alias in entry.get("aliases") or ()}
        names.discard(entry["name"].lower())
        requirers = set().union(*(required_by_name.get(n, set()) for n in names))
        added = (requirers & entry.get("_cores", set())) - entry.get("_required_by", set())
        if added:
            entry["_required_by"] = entry.get("_required_by", set()) | added
            entry["required"] = True


def brought_by(file_entry: dict, emu_name: str) -> set[str]:
    """The core and build that need the file brought, empty when the
    emulator installs it. An entry read without layer (a test, a caller of
    its own) is brought by its core's libretro build."""
    brought = file_entry.get("_brought", f"{emu_name}:libretro")
    return {brought} if brought else set()


def has_exploitable_data(entry: dict) -> bool:
    """Check if an entry has any data beyond its name that can drive verification.

    Applied AFTER merging all cores so entries benefit from enrichment by
    sibling cores before being judged empty.
    """
    return bool(
        lists_hashes(entry)
        or entry.get("path")
        or entry.get("size")
        or entry.get("min_size")
        or entry.get("max_size")
        or entry.get("validation")
        or entry.get("contents")
    )


def _system_dir_files(profile: dict, standalone: bool) -> list[dict]:
    """Entries of the build the platform runs, read from the system directory.

    An entry the platform's launchers leave outside the BIOS tree
    (``unplaced``) is not, nor one placed below its roms or an emulator
    folder (``root``): the platform has no file of its own there.
    """
    return [
        f for f in filter_files_by_mode(profile.get("files", []), standalone=standalone)
        if read_from_system_dir(f) and not f.get("unplaced") and f.get("root") not in OUTER_ROOTS
    ]


def _archives_not_members(files: list[dict]) -> list[dict]:
    """A profile's entries with the members of each archive folded into it.

    fbneo declares bubsys.zip as the ROMs it holds, each carrying
    `archive: bubsys.zip`. The platform reads the archive, never a member:
    as loose files the members were added to RetroArch's System.dat, and
    the 480-byte boot.bin was filed under the Dreamcast by its bare name.
    The archive stands in their place with the members as its contents,
    the shape a profile that declares the archive itself already has.
    """
    out: list[dict] = []
    archives: dict[tuple[str, str], dict] = {}
    for fe in files:
        archive = fe.get("archive")
        if not archive:
            out.append(fe)
            continue
        key = (archive, fe.get("system", ""))
        entry = archives.get(key)
        if entry is None:
            entry = {"name": archive, "category": "bios_zip", "contents": [],
                     "_brought": None}
            if fe.get("system"):
                entry["system"] = fe["system"]
            if fe.get("source_ref") is not None:
                entry["source_ref"] = fe["source_ref"]
            archives[key] = entry
            out.append(entry)
        if fe.get("required"):
            entry["required"] = True
        # The archive is brought when one member is: gngeo_data.zip, every
        # member of it installed by make install, is not a file to copy.
        if "_brought" not in fe:
            entry.pop("_brought", None)
        elif "_brought" in entry and entry["_brought"] is None:
            entry["_brought"] = fe["_brought"]
        entry["contents"].append({
            field: fe[field]
            for field in ("name", "size", "crc32", "sha1", "md5")
            if fe.get(field) is not None
        })
    return out


def _sizes(entry: dict) -> tuple[set[int], tuple[int, float] | None]:
    """The sizes an entry admits: exact values, then its window or None.

    An entry that declares no size at all admits every size, an unbounded
    window. Exact sizes alone leave no window (size_refusal).
    """
    raw = entry.get("size")
    values = raw if isinstance(raw, list) else [raw]
    exact = {int(v) for v in values if isinstance(v, int) and not isinstance(v, bool)}
    low, high = entry.get("min_size"), entry.get("max_size")
    low = low if isinstance(low, int) else None
    high = high if isinstance(high, int) else None
    if low is None and high is None:
        return exact, None if exact else (0, float("inf"))
    return exact, (low or 0, float("inf") if high is None else high)


def sizes_clash(a: dict, b: dict) -> bool:
    """No size both entries admit, lists and windows included."""
    exact_a, window_a = _sizes(a)
    exact_b, window_b = _sizes(b)

    def inside(value: int, window: tuple[int, float] | None) -> bool:
        return window is not None and window[0] <= value <= window[1]

    if exact_a & exact_b:
        return False
    if any(inside(v, window_b) for v in exact_a) or any(inside(v, window_a) for v in exact_b):
        return False
    if window_a and window_b:
        return max(window_a[0], window_b[0]) > min(window_a[1], window_b[1])
    return True


def _identity(entry: dict, db: dict | None) -> dict:
    """The entry with the hashes and size the database knows for its hash."""
    probe = {k: entry[k] for k in ("sha1", "md5", "crc32", "size") if entry.get(k)}
    if db and probe and not any(isinstance(v, list) for v in probe.values()):
        enrich_hashes(probe, db)
    return {**entry, **{k: v for k, v in probe.items() if not entry.get(k)}}


def _identity_values(entry: dict) -> set[str]:
    """Every hash an identity declares."""
    return {v for values in declared_hashes(entry).values() for v in values}


def _declaration_verdict(entry: dict, declaration: dict, db: dict | None) -> str:
    """same, other or undecided: can a platform declaration be this file?

    A shared hash proves it. Sizes no value of which agrees refute it, as
    name_match_size_ok refutes a candidate. Two hashes at one size are two
    revisions of one slot, as slots.py reads them, so they refute nothing.
    The size the database holds for a declared hash counts as declared:
    Batocera's BK BASIC10.ROM names only an md5, of a 24576-byte file, and
    clk's 16 KB Oric basic10.rom was filed under the BK beside it.
    """
    ours, theirs = _identity(entry, db), _identity(declaration, db)
    if _identity_values(ours) & _identity_values(theirs):
        return "same"
    if sizes_clash(ours, theirs):
        return "other"
    return "undecided"


@dataclass(frozen=True)
class SystemMap:
    """How a profile's systems and entries map onto a platform's systems."""

    platform_sys_ids: set[str]
    # Every platform declaration of a name, in the platform's order. The
    # last one used to win, whatever the content.
    declared_by_name: dict[str, list[tuple[str, dict]]]
    # Normalized ID -> platform system ID. Walked in the platform's order,
    # not the set's: two IDs normalizing alike went to whichever the hash
    # seed put last.
    norm_to_platform: dict[str, str]
    db: dict | None

    @classmethod
    def of(cls, config: dict, db: dict | None) -> SystemMap:
        declared_by_name: dict[str, list[tuple[str, dict]]] = {}
        for psid, sys_data in config.get("systems", {}).items():
            for fe in sys_data.get("files", []):
                fname = fe.get("name", "").lower()
                if fname:
                    declared_by_name.setdefault(fname, []).append((psid, fe))
        norm_to_platform: dict[str, str] = {}
        for psid in config.get("systems", {}):
            norm_to_platform.setdefault(norm_system_id(psid), psid)
        return cls(
            set(config.get("systems", {}).keys()), declared_by_name, norm_to_platform, db,
        )

    def map_sys_id(self, profile_sid: str) -> str:
        """Map a profile system ID to the platform's system ID."""
        if profile_sid in self.platform_sys_ids:
            return profile_sid
        return self.norm_to_platform.get(norm_system_id(profile_sid), profile_sid)

    def attribute(self, fe: dict, own: str | None, on_platform: set[str]) -> list[str]:
        """The platform systems an entry belongs to, [] when nothing decides.

        A declaration of the same name settles the system only when it can
        be the same file: a shared hash, or no contradicting size. fmsx's
        16 KB DISK.ROM is not quasi88's 2 KB disk.rom, and dosbox's SC-55
        ROM1.BIN is not galaksija's. The same content declared under two
        systems is filed under both.
        """
        verdicts = [
            (psid, _declaration_verdict(fe, decl, self.db))
            for psid, decl in self.declared_by_name.get(fe.get("name", "").lower(), [])
        ]
        same = sorted({psid for psid, v in verdicts if v == "same"})
        undecided = sorted({psid for psid, v in verdicts if v == "undecided"})
        if own is not None:
            mapped = self.map_sys_id(own)
            if any(psid == mapped and v != "other" for psid, v in verdicts):
                return [mapped]
            if same:
                return same
            if len(undecided) == 1:
                return undecided
            return [mapped]
        if same:
            return same
        if len(undecided) == 1:
            return undecided
        if undecided:
            ours = [psid for psid in undecided if psid in on_platform]
            return ours if len(ours) == 1 else []
        return [next(iter(on_platform))] if len(on_platform) == 1 else []

    def targets(self, fe: dict, profile: dict, on_platform: set[str]) -> list[str]:
        """The platform systems an entry is filed under."""
        profile_sid = fe.get("system", "")
        sys_ids = profile.get("systems", [])
        if profile_sid:
            own: str | None = profile_sid
        elif len(sys_ids) == 1:
            own = sys_ids[0]
        elif not sys_ids:
            # A profile that names no system: a platform declaration of
            # the same file files it, and the placeholder takes only a
            # name the platform does not declare. mess2015's hiscore.dat
            # beside the arcade one put an "unknown" section in System.dat.
            own = None
        else:
            # A multi-system profile's entry without a system is filed by
            # the platform's own declaration of the same file, or the one
            # profile system the platform has. Otherwise it is not filed:
            # the first system was a guess, and CLK's Apple, Mac, ZX and
            # Amiga ROMs went to RomM as Amstrad CPC firmware.
            own = None
        sys_targets = self.attribute(fe, own, on_platform)
        if not sys_ids and not profile_sid and not sys_targets \
                and fe.get("name", "").lower() not in self.declared_by_name:
            sys_targets = [self.map_sys_id("unknown")]
        return sys_targets


def cover(
    system_cores: dict[str, dict[str, set[str]]], sys_id: str, kind: str, emu_name: str,
) -> None:
    sys_cov = system_cores.setdefault(
        sys_id,
        {
            "profiled": set(),
            "unprofiled": set(),
        },
    )
    sys_cov[kind].add(emu_name)


def platform_entries(
    emu_name: str, profile: dict, launches: PlatformLaunches, platform_name: str,
) -> list[dict]:
    # The pack's rule (validation.deliverable), per build: a file the
    # emulator installs is kept and marked, one the launcher never opens
    # is left out.
    return _archives_not_members([
        {
            **fe,
            "_opens_by_name": opens_by_name(fe, profile, standalone),
            "_brought": None if installed_with_emulator(fe, platform_name)
            else f"{emu_name}:{'standalone' if standalone else 'libretro'}",
        }
        for view, standalone in platform_layouts(emu_name, profile, launches)
        for fe in _system_dir_files(view, standalone)
        if not unread_on(fe, platform_name)
    ])


def serialize_systems(
    systems: dict[str, dict], system_cores: dict[str, dict[str, set[str]]],
) -> None:
    # Convert sets to sorted lists for serialization
    for sys_id, sys_data in systems.items():
        for fe in sys_data.get("files", []):
            fe.pop("_hash_by", None)
            fe.pop("_region_void", None)
            fe["_cores"] = sorted(fe.get("_cores", set()))
            fe["_required_by"] = sorted(fe.get("_required_by", set()))
            one_of = fe.pop("_one_of", None)
            if one_of:
                fe["one_of"] = sorted(one_of)
            fe["_named_by"] = sorted(fe.get("_named_by", set()))
            fe["_brought_by"] = sorted(fe.get("_brought_by", set()))
            if not fe["_brought_by"]:
                fe["bundled"] = True
            fe["_source_refs"] = sorted(fe.get("_source_refs", set()))
        # Add per-system coverage
        cov = system_cores.get(sys_id, {})
        sys_data["_coverage"] = {
            "cores_profiled": sorted(cov.get("profiled", set())),
            "cores_unprofiled": sorted(cov.get("unprofiled", set())),
        }
