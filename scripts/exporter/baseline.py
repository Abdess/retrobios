"""Reconciliation of a platform's own declarations with the ground truth.

An export is not the truth rendered in a native syntax. It is the platform's
file, corrected: what the truth can prove is applied, what it says nothing
about is left alone, and what it knows and the platform lacks is added. A
platform that loses two thirds of its systems to an export cannot use it.

Systems are keyed by the identifier the platform itself uses. Several of our
slugs collapse onto one native id (Recalbox files pcengine, pcenginecd and
supergrafx under one slug) and one slug can carry several native ids, so the
grouping is rebuilt from the per-file native_system the scrapers record.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import _norm_system_id

HASH_FIELDS = ("sha1", "md5", "sha256", "crc32")


def _hash_values(entry: dict, field_name: str) -> list[str]:
    """Return a hash field as a list, whatever shape it was written in."""
    raw = entry.get(field_name)
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(v).strip().lower() for v in raw if str(v).strip()]
    return [v.strip().lower() for v in str(raw).split(",") if v.strip()]


def checked_hashes(entry: dict | None) -> dict | None:
    """The truth entry with only the hashes its code checks.

    `validation:` names what the code verifies. Where a checked hash names
    one value, the content is pinned and every hash describes it. Where
    the code checks no hash, or accepts several values, a hash it does not
    name describes one revision among those it accepts: dosbox checks
    MT32_CONTROL.ROM against nine sha1, and the one md5 beside them
    replaced System.dat's, another accepted revision. Such a value still
    pairs a renamed file, it never corrects or fills one.

    `hash_conflict` marks an entry whose cores declare different values: the
    truth kept the first core's, so its hashes describe one revision among
    those the cores accept. armsx2 and yaps2 disagree on GameIndex.yaml, and
    armsx2's revision replaced System.dat's line for LRPS2.
    """
    if not entry:
        return entry
    if entry.get("hash_conflict"):
        return {k: v for k, v in entry.items() if k not in HASH_FIELDS}
    if entry.get("validation") is None:
        return entry
    raw = entry["validation"]
    if isinstance(raw, dict):
        kinds = {str(k) for values in raw.values() for k in values or ()}
    elif isinstance(raw, list):
        kinds = {str(k) for k in raw}
    else:
        kinds = {str(raw)}
    checked = [f for f in HASH_FIELDS if f in kinds and _hash_values(entry, f)]
    if checked and all(len(set(_hash_values(entry, f))) == 1 for f in checked):
        return entry
    return {k: v for k, v in entry.items() if k not in HASH_FIELDS or k in kinds}


def comparable(entry: dict | None) -> dict:
    """The entry with only the hashes the truth can be compared with.

    Recalbox hashes a .zip by its members (Bios.cpp:64-68 calls
    Zip::Md5Composite, which feeds each member's bytes in name order into
    one md5), never by the container's bytes. Its md5 on an archive is that
    composite, a digest no profile declares: read as a container md5 it was
    replaced by geolith's, which Recalbox never computes.
    """
    if not entry or entry.get("zip_digest") != "composite":
        return entry or {}
    return {k: v for k, v in entry.items() if k != "md5"}


def contradicted_hashes(truth_entry: dict, platform_entry: dict | None) -> list[str]:
    """The hash fields a platform entry declares against the truth.

    A field contradicts when both sides declare it without a value in
    common, among the hashes the code checks and the platform values a
    profile can be compared with. export_native corrects exactly these and
    diff_truth reports them: the diff read three fields and let one shared
    value settle all of them, so it stayed silent on an md5 or a sha256
    the export rewrote.
    """
    checked = checked_hashes(truth_entry) or {}
    theirs = comparable(platform_entry)
    return [
        field_name for field_name in HASH_FIELDS
        if (ours := set(_hash_values(checked, field_name)))
        and (held := set(_hash_values(theirs, field_name)))
        and not ours & held
    ]


def is_label(entry: dict) -> bool:
    """A name only content-scanning cores give: no core opens that file.

    DuckStation identifies its BIOS by MD5 in a folder it scans, so
    scph1001_v20.bin names nothing a platform could check by path.
    """
    return bool(entry.get("_cores")) and "_named_by" in entry and not entry["_named_by"]


def _is_placeholder(name: str) -> bool:
    return "<" in name or ">" in name or "*" in name


def _field_sets(entry: dict | None) -> dict[str, set[str]]:
    return {f: set(_hash_values(entry or {}, f)) for f in HASH_FIELDS}


def _single_size(value: object) -> int | None:
    """One size, or None: a list names several accepted revisions, which a
    single size field cannot state (int() on it stopped the whole export)."""
    if isinstance(value, list):
        distinct = {int(v) for v in value}
        return distinct.pop() if len(distinct) == 1 else None
    return int(value)


@dataclass
class NativeFile:
    """One file as the platform will read it, after correction."""

    name: str
    destination: str
    native_system: str
    platform: dict | None = None
    truth: dict | None = None
    corrections: list[str] = field(default_factory=list)
    # Hash fields the platform left empty and the truth fills.
    filled: list[str] = field(default_factory=list)
    # An addition filed under our own slug: the platform names no such system.
    foreign_system: bool = False
    # For an addition, each core that wants it as (runs standalone, name the
    # platform gives it), empty when no core the platform runs is named.
    runners: list[tuple[bool, str]] = field(default_factory=list)
    # The platform reads this file's md5 as a composite of its members
    # (Recalbox on a .zip) or as one member's (Batocera's zippedFile, which
    # checkInsideZip compares inside the archive): the truth's md5 describes
    # the container and can be neither compared with it nor written in its
    # place.
    composite_md5: bool = False
    # Every truth entry of the system that answers to this platform entry's
    # name, whichever one the pairing took: the element names its cores, and
    # each core's own entry for the file says whether that core needs it.
    namesakes: list[dict] = field(default_factory=list)

    @property
    def origin(self) -> str:
        if self.platform is not None and self.truth is not None:
            return "both"
        return "platform" if self.platform is not None else "truth"

    @property
    def _checked_truth(self) -> dict:
        """The truth's hashes that can overrule the platform's. An addition
        has no platform value to overrule and keeps them all."""
        if self.platform is None:
            return self.truth or {}
        return checked_hashes(self.truth) or {}

    def _identity_source(self) -> str:
        """Which side's content fields describe the file: one side, or both.

        Mixing them field by field wrote the truth's size and crc beside the
        platform's sha1, a record no file satisfies. The truth decides alone
        only on a contradiction: a hash both sides declare without a value in
        common, or two declared sizes. Different fields prove nothing: the
        truth's crc32 beside Batocera's md5 for bios7.bin is one dump, and
        reading it as a contradiction emptied the md5 the frontend checks.
        """
        truth, plat = _field_sets(self._checked_truth), _field_sets(comparable(self.platform))
        if self.composite_md5:
            truth["md5"] = set()
        if not any(truth.values()):
            return "platform"
        if not any(plat.values()):
            return "truth"
        shared = [f for f in HASH_FIELDS if truth[f] and plat[f]]
        if any(truth[f] & plat[f] for f in shared):
            return "both"
        return "truth" if shared or self._sizes_differ() else "both"

    def _sizes_differ(self) -> bool:
        t_size = (self.truth or {}).get("size")
        p_size = (self.platform or {}).get("size")
        return isinstance(t_size, int) and isinstance(p_size, int) and t_size != p_size

    def hashes(self, field_name: str) -> list[str]:
        """Accepted values for a hash, truth first when it has an opinion.

        The truth is read from the emulator's source. The platform list is a
        secondary source. When both speak and disagree, the truth decides and
        the divergence is recorded, never silently merged: an emulator that
        rejects a file will reject it whatever the platform declares.
        """
        if field_name == "md5" and self.composite_md5:
            return _hash_values(self.platform or {}, field_name)
        truth_values = _hash_values(self._checked_truth, field_name)
        platform_values = _hash_values(self.platform or {}, field_name)
        source = self._identity_source()
        if source == "platform":
            return platform_values
        if source == "truth":
            return truth_values
        if not truth_values:
            return platform_values
        if not set(truth_values) & set(platform_values):
            return truth_values
        # Nothing to add: the platform's own order stands. Truth first
        # rewrote Recalbox's msx/CARTS.SHA md5 list with the same two values
        # swapped, a diff line that changes nothing the frontend checks.
        if set(truth_values) <= set(platform_values):
            return platform_values
        # Keep the platform's extra accepted revisions alongside ours.
        return truth_values + [v for v in platform_values if v not in truth_values]

    def hash(self, field_name: str) -> str:
        values = self.hashes(field_name)
        return values[0] if values else ""

    def record_hash(self, field_name: str) -> str:
        """One value of a record whose fields all describe one dump.

        A clrmamepro rom line or a RomM entry carries a single crc, md5 and
        sha1: taking each field's first accepted value wrote syscard2.pce
        with the v2.0 crc (the truth's first) beside the v2.1 md5 and sha1
        (System.dat's), a record no file satisfies. When the two sides
        agree on the dump, the platform's record is kept whole, its value
        chosen among those the truth accepts. A field only the truth names
        is written when it names one value, which is then that dump's.
        """
        if field_name == "md5" and self.composite_md5:
            values = _hash_values(self.platform or {}, field_name)
            return values[0] if values else ""
        source = self._identity_source()
        truth_values = _hash_values(self._checked_truth, field_name)
        platform_values = _hash_values(self.platform or {}, field_name)
        if source == "truth":
            return truth_values[0] if truth_values else ""
        if source == "platform" or not truth_values:
            return platform_values[0] if platform_values else ""
        if platform_values:
            accepted = [v for v in platform_values if v in truth_values]
            return (accepted or truth_values)[0]
        return truth_values[0] if len(truth_values) == 1 else ""

    @property
    def required(self) -> bool:
        if self.truth is not None and self.truth.get("required") is not None:
            return bool(self.truth["required"])
        if self.platform is not None and self.platform.get("required") is not None:
            return bool(self.platform["required"])
        if self.truth is not None and self.truth.get("one_of_required") is not None:
            return bool(self.truth["one_of_required"])
        return True

    @property
    def priority(self) -> int | None:
        """Where the code looks for this file, lowest first.

        DuckStation's FindBIOSImageInDirectory keeps the image whose
        priority is lower, and a search list a core walks in order maps
        onto it as 1, 2, 3. Where cores disagree this is the best rank any
        of them gives: nothing is dropped on it, so a file that is some
        core's first choice is read early. None when nothing states one.
        """
        for entry in (self.truth, self.platform):
            if entry and entry.get("priority") is not None:
                return int(entry["priority"])
        return None

    def size(self) -> int | None:
        """Size of the content the written hashes describe.

        hashes() keeps the platform's values when the truth has none, so the
        truth's size is only taken when the truth also speaks for the hash:
        a name-matched 480-byte fbneo boot.bin turned RomM's Dreamcast
        boot.bin into size 480 beside its 2 MB md5, which never verifies.
        When the truth contradicts the platform's hash, the platform's size
        describes the dump the truth rejects: geolith's neocdz.zip md5 went
        out beside System.dat's 953078 bytes, a record no file satisfies.
        """
        source = self._identity_source()
        order = {
            "platform": (self.platform, self.truth),
            "truth": (self.truth,),
        }.get(source, (self.truth, self.platform))
        # A list names every size the code accepts (geargrafx's syscard3.pce,
        # headerless or headered). It states no single size, but it still
        # admits the one the platform writes: System.dat's 262144 for the
        # same md5 lost its size field when the list came first.
        accepted: set[int] | None = None
        for entry in order:
            if not entry or not entry.get("size"):
                continue
            single = _single_size(entry["size"])
            if single is None:
                if accepted is None:
                    accepted = {int(v) for v in entry["size"]}
                continue
            if accepted is None or single in accepted:
                return single
        return None

    def native(self, key: str, default: object = "") -> object:
        """Read a field the platform declares and we only carry through."""
        for entry in (self.platform, self.truth):
            if entry and entry.get(key) not in (None, ""):
                return entry[key]
        return default

    def cores(self) -> list[str]:
        """Cores that want this file, as Recalbox writes them: the declared
        value, else each runner, a standalone bare and a core under
        libretro/. A profile key is not a name the platform knows:
        `libretro/duckstation` named no core Recalbox runs."""
        declared = self.native("core", "")
        if declared:
            return [c.strip() for c in str(declared).split(",") if c.strip()]
        return [name if standalone else f"libretro/{name}" for standalone, name in self.runners]


@dataclass
class NativeSystem:
    """One system as the platform names it."""

    native_id: str
    name: str = ""
    files: list[NativeFile] = field(default_factory=list)
    from_platform: bool = False

    @property
    def origin(self) -> str:
        return "platform" if self.from_platform else "truth"


@dataclass
class Report:
    """What the reconciliation changed, so the caller can say it out loud."""

    systems_kept: int = 0
    systems_added: int = 0
    files_kept: int = 0
    files_added: int = 0
    hashes_corrected: list[str] = field(default_factory=list)
    required_corrected: list[str] = field(default_factory=list)
    # Entries only content-scanning cores name: never written as files.
    labels: int = 0
    # Additions to a system spanning several native ids that their cores do
    # not tell apart, as truth system/name: not written.
    unattributed: list[str] = field(default_factory=list)

    @property
    def corrections(self) -> int:
        return len(self.hashes_corrected) + len(self.required_corrected)


def _native_id_of(sys_key: str, sys_data: dict, file_entry: dict) -> str:
    """The platform's own id for the system a file belongs to."""
    return (
        file_entry.get("native_system")
        or sys_data.get("native_id")
        or sys_key
    )


def _match_key(entry: dict) -> tuple[str, str]:
    dest = str(entry.get("destination") or entry.get("path") or entry.get("name", ""))
    return dest.casefold(), str(entry.get("name", "")).casefold()


def _names(entry: dict) -> set[str]:
    """The names an entry answers to: its own and the aliases it declares."""
    return {
        str(n).casefold()
        for n in (entry.get("name", ""), *(entry.get("aliases") or []))
        if n
    }


def by_destination(truth_entry: dict, platform_entry: dict) -> bool:
    """The platform's destination ends in the path the truth declares.

    Dolphin writes dolphin-emu/Sys/GC/USA/IPL.bin for the truth's
    GC/USA/IPL.bin. A bare name is no path: dc/boot.bin ends in /boot.bin,
    and fbneo's 480-byte boot.bin is not that 2 MB Dreamcast BIOS.
    """
    t_dest = _match_key(truth_entry)[0]
    theirs = _match_key(platform_entry)[0]
    if not t_dest:
        return False
    return theirs == t_dest or ("/" in t_dest and theirs.endswith("/" + t_dest))


def by_name(truth_entry: dict, platform_entry: dict) -> bool:
    """One of the truth's names, in the same directory, at the same size."""
    t_dest = _match_key(truth_entry)[0]
    theirs_dest, theirs = _match_key(platform_entry)
    if not theirs or theirs not in _names(truth_entry):
        return False
    # Two declared directories that differ name two files: the truth's
    # BeebFile/BIOS.rom is not Recalbox's np2kai/bios.rom.
    if "/" in t_dest and "/" in theirs_dest and not theirs_dest.endswith(
        "/" + t_dest.rsplit("/", 1)[0].rsplit("/", 1)[-1] + "/" + theirs
    ):
        return False
    # A shared name with two declared sizes is two files: fbneo's 480-byte
    # boot.bin is not RomM's 2 MB Dreamcast boot.bin.
    t_size = truth_entry.get("size")
    p_size = platform_entry.get("size")
    return not (isinstance(t_size, int) and isinstance(p_size, int) and t_size != p_size)


def by_hash(truth_entry: dict, platform_entry: dict) -> bool:
    """A value on any of the four hash fields in common: a renamed file."""
    ours = {v for f in HASH_FIELDS for v in _hash_values(truth_entry, f)}
    if not ours:
        return False
    theirs = comparable(platform_entry)
    return bool(ours & {v for f in HASH_FIELDS for v in _hash_values(theirs, f)})


def _contradicts(truth_entry: dict, platform_entry: dict) -> bool:
    """A hash both entries declare, without a value in common."""
    platform_entry = comparable(platform_entry)
    return any(
        (ours := set(_hash_values(truth_entry, f)))
        and (theirs := set(_hash_values(platform_entry, f)))
        and not ours & theirs
        for f in HASH_FIELDS
    )


def _agreeing(test: Callable[[dict, dict], bool]) -> Callable[[dict, dict], bool]:
    def agrees(truth_entry: dict, platform_entry: dict) -> bool:
        return test(truth_entry, platform_entry) and not _contradicts(
            truth_entry, platform_entry
        )
    return agrees


_PAIRING_TESTS = (
    _agreeing(by_destination),
    _agreeing(by_name),
    by_hash,
    by_destination,
    by_name,
)


def pair_entries(truth_entries: list[dict], candidates: list[dict]) -> dict[int, int]:
    """Which platform entry each truth entry describes, as index -> index.

    The one rule export_native and diff_truth read. Each test runs over
    every truth entry and every candidate before the next one does:
    claimed entry by entry, dosbox-x's system.rom took np2kai/BIOS.ROM by
    its alias before np2kai's own np2kai/bios.rom was tried, and wrote an
    IBM PCjr md5 on it. A path or a name that contradicts a hash comes
    after the hash: the truth's MSX.rom carries bluemsx's path and fmsx's
    md5, and fmsx's own line holds that md5. An entry never answers for two.
    """
    pairs: dict[int, int] = {}
    claimed: set[int] = set()
    for test in _PAIRING_TESTS:
        for t_index, truth_entry in enumerate(truth_entries):
            # A label answers for no name or path, only for its content.
            if t_index in pairs or (test is not by_hash and is_label(truth_entry)):
                continue
            for index, candidate in enumerate(candidates):
                if index not in claimed and test(truth_entry, candidate):
                    pairs[t_index] = index
                    claimed.add(index)
                    break
    return pairs


def platform_declares(truth_entry: dict, candidates: list[dict]) -> bool:
    """A file another truth entry already claimed is still the platform's
    file, not one it lacks: scph101.bin, declared by two PSX cores. The
    same content under another name is not: fuse opens fuse/128-1.rom by
    name, and Recalbox's fuse/128p-1.rom holding that dump does not serve
    it."""
    return any(
        by_destination(truth_entry, c) or by_name(truth_entry, c) for c in candidates
    )


def build_native_model(
    truth: dict,
    scraped: dict | None,
) -> tuple[dict[str, NativeSystem], Report]:
    """Rebuild the platform's systems, corrected by the truth.

    Returns the systems keyed by native id, in the platform's own order
    first and truth-only additions after, plus what changed.
    """
    report = Report()
    systems: dict[str, NativeSystem] = {}

    scraped_systems = (scraped or {}).get("systems", {})
    composite_zips = (scraped or {}).get("zip_digest") == "composite"

    # Pass 1: the platform's own file, grouped as the platform groups it.
    for sys_key, sys_data in scraped_systems.items():
        for file_entry in sys_data.get("files", []):
            native_id = _native_id_of(sys_key, sys_data, file_entry)
            system = systems.get(native_id)
            if system is None:
                system = NativeSystem(
                    native_id=native_id,
                    name=str(file_entry.get("native_name") or sys_data.get("name", "")),
                    from_platform=True,
                )
                systems[native_id] = system
                report.systems_kept += 1
            name = str(file_entry.get("name", ""))
            destination = str(file_entry.get("destination") or name)
            system.files.append(
                NativeFile(
                    name=name,
                    destination=destination,
                    native_system=native_id,
                    platform=file_entry,
                    composite_md5=file_entry.get("zip_digest") == "composite"
                    or bool(file_entry.get("zipped_file")),
                )
            )
            report.files_kept += 1

    # Which native ids a truth system may contribute to.
    norm_to_scraped: dict[str, str] = {
        _norm_system_id(key): key for key in scraped_systems
    }
    # Every system the platform names, files or none: an addition elsewhere
    # is filed under our own slug.
    platform_ids = {
        native_id
        for key, sys_data in scraped_systems.items()
        for native_id in (
            sys_data.get("native_id") or key,
            *(_native_id_of(key, sys_data, fe) for fe in sys_data.get("files", [])),
        )
    }
    native_by_norm: dict[str, str] = {}
    for system in systems.values():
        native_by_norm.setdefault(_norm_system_id(system.native_id), system.native_id)

    def _target_native_ids(truth_sid: str) -> tuple[list[str], bool]:
        """The native ids a truth system spans, and whether the first one
        is where an addition belongs without asking which core reads it."""
        scraped_key = truth_sid if truth_sid in scraped_systems else None
        if scraped_key is None:
            scraped_key = norm_to_scraped.get(_norm_system_id(truth_sid))
        if scraped_key is not None:
            sys_data = scraped_systems[scraped_key]
            ids = {
                _native_id_of(scraped_key, sys_data, fe)
                for fe in sys_data.get("files", [])
            }
            if not ids:
                return [sys_data.get("native_id") or scraped_key], True
            # A file the platform does not declare joins the system's primary
            # id, not whichever of its native ids sorts first: Recalbox files
            # pcengine, pcenginecd and supergrafx under one slug, and an
            # addition belongs to the one the system is named for.
            primary = sys_data.get("native_id")
            ordered = sorted(ids)
            if primary in ids:
                ordered.remove(primary)
                ordered.insert(0, primary)
            return ordered, primary in ids or len(ordered) == 1
        direct = native_by_norm.get(_norm_system_id(truth_sid))
        return ([direct] if direct else [truth_sid]), True

    # Pass 2: apply the truth onto that grouping.
    for truth_sid in sorted(truth.get("systems", {})):
        truth_sys = truth["systems"][truth_sid]
        truth_files = truth_sys.get("files", [])
        if not truth_files:
            continue

        target_ids, settled_id = _target_native_ids(truth_sid)
        truth_files = [
            entry for entry in truth_files
            if (name := str(entry.get("name", "")))
            and not name.startswith("_") and not _is_placeholder(name)
        ]
        candidates = [
            candidate
            for native_id in target_ids
            for candidate in systems.get(native_id, NativeSystem(native_id)).files
            if candidate.truth is None
        ]
        pairs = pair_entries(truth_files, [c.platform or {} for c in candidates])
        # The cores that read what the platform files under each native id,
        # from the truth entries its declarations pair with.
        readers: dict[str, set[str]] = {}
        for t_index, index in pairs.items():
            readers.setdefault(candidates[index].native_system, set()).update(
                truth_files[t_index].get("_cores") or ()
            )
        for candidate in (
            c
            for native_id in target_ids
            for c in systems.get(native_id, NativeSystem(native_id)).files
            if c.platform is not None
        ):
            own = str(candidate.name).casefold()
            candidate.namesakes.extend(
                entry for entry in truth_files if own in _names(entry)
            )

        for t_index, truth_entry in enumerate(truth_files):
            name = str(truth_entry["name"])
            index = pairs.get(t_index)
            matched = candidates[index] if index is not None else None

            if matched is not None:
                matched.truth = truth_entry
                checked = checked_hashes(truth_entry) or {}
                contradicted = contradicted_hashes(truth_entry, matched.platform)
                for field_name in HASH_FIELDS:
                    if field_name == "md5" and matched.composite_md5:
                        continue
                    if field_name in contradicted:
                        matched.corrections.append(field_name)
                        report.hashes_corrected.append(
                            f"{matched.native_system}/{matched.name} {field_name}"
                        )
                    elif _hash_values(checked, field_name) and not _hash_values(
                        comparable(matched.platform), field_name
                    ):
                        matched.filled.append(field_name)
                t_req = truth_entry.get("required")
                p_req = (matched.platform or {}).get("required")
                # A file a core takes as one of a set has no requirement of
                # its own: a platform line cannot say "one of these", so
                # truth leaves its value as written rather than claim
                # every member optional or every member needed.
                if (
                    t_req is not None
                    and p_req is not None
                    and bool(t_req) != bool(p_req)
                    and not (truth_entry.get("one_of_required") and not t_req)
                ):
                    matched.corrections.append("required")
                    report.required_corrected.append(
                        f"{matched.native_system}/{matched.name}"
                    )
                continue

            if is_label(truth_entry):
                report.labels += 1
                continue
            # The emulator installs it: no user is asked to bring it.
            if truth_entry.get("bundled"):
                continue

            # A file another core's entry already claimed is still the
            # platform's file, not a new one: scph101.bin, declared by two
            # PSX cores, was written into RetroDECK's manifest a second time.
            declared = [
                candidate.platform
                for native_id in target_ids
                for candidate in systems.get(native_id, NativeSystem(native_id)).files
                if candidate.platform is not None
            ]
            if platform_declares(truth_entry, declared):
                continue

            # The truth knows a file the platform does not declare. Across
            # several native ids and no primary, it joins the one whose files
            # its cores read: RetroDECK's arcade spans mame and fbneo, and
            # MAME device archives were filed as FBNeo BIOS because fbneo
            # sorts first. With no single answer it is not written.
            native_id = target_ids[0]
            if not settled_id:
                wanted = set(truth_entry.get("_cores") or ())
                shared = {nid: len(readers.get(nid, set()) & wanted) for nid in target_ids}
                best = max(shared.values())
                winners = [nid for nid, count in shared.items() if count == best]
                if not best or len(winners) > 1:
                    report.unattributed.append(f"{truth_sid}/{name}")
                    continue
                native_id = winners[0]
            system = systems.get(native_id)
            if system is None:
                system = NativeSystem(native_id=native_id, from_platform=False)
                systems[native_id] = system
                report.systems_added += 1
            destination = str(
                truth_entry.get("path") or truth_entry.get("destination") or name
            )
            system.files.append(
                NativeFile(
                    name=name,
                    destination=destination,
                    native_system=native_id,
                    truth=truth_entry,
                    foreign_system=native_id not in platform_ids,
                    composite_md5=composite_zips and name.lower().endswith(".zip"),
                )
            )
            report.files_added += 1

    # A reader takes the files in the order the list gives, so the one the
    # code looks for first is named first. Only what we add is ordered: what
    # the platform already wrote keeps the place the platform gave it.
    for system in systems.values():
        head = [fe for fe in system.files if fe.platform is not None]
        tail = [fe for fe in system.files if fe.platform is None]
        system.files = head + search_order(tail)

    _attach_runners(systems, scraped)
    return systems, report


def _attach_runners(systems: dict[str, NativeSystem], scraped: dict | None) -> None:
    """Name the cores behind each addition the way the platform names them.

    The platform lists its cores by its own names (Batocera's
    `mednafen_psx`, Recalbox's `mednafen_psx`), our truth by profile key
    (`beetle_psx`), and a profile's `cores:` holds the names it answers to.
    The build a platform runs an emulator as decides the runner, and the
    truth says which build needs the file (`_brought_by`): ROCKNIX's
    armsx2-sa installs pcsx2/resources itself, the libretro build does not.
    """
    if not scraped:
        return
    from common import load_emulator_profiles, runs_standalone

    declared = scraped.get("cores")
    libretro = {str(c) for c in declared} if isinstance(declared, list) else set()
    standalone = {str(c) for c in scraped.get("standalone_cores") or []}
    profiles = load_emulator_profiles(str(Path(__file__).resolve().parents[2] / "emulators"))
    for system in systems.values():
        for fe in system.files:
            if fe.platform is not None or not fe.truth:
                continue
            runners: list[tuple[bool, str]] = []
            brought = fe.truth.get("_brought_by")
            layers = (
                sorted((key, build == "standalone") for key, _, build in
                       (b.partition(":") for b in brought))
                if brought is not None
                else [(key, runs_standalone(key, profiles.get(key, {}), standalone))
                      for key in sorted(fe.truth.get("_cores") or ())]
            )
            for key, as_standalone in layers:
                profile = profiles.get(key, {})
                names = [key, *(str(c) for c in profile.get("cores") or [])]
                if as_standalone:
                    name = next((n for n in names if n in standalone), None)
                    runner = (True, name) if name else None
                else:
                    name = next((n for n in names if n in libretro - standalone), None) \
                        or next((n for n in names if n in libretro), None)
                    runner = (False, name) if name else None
                if runner and runner not in runners:
                    runners.append(runner)
            fe.runners = runners


def search_order(files: list[NativeFile]) -> list[NativeFile]:
    """Order files the way the code looks for them, best first.

    `priority:` is that order where the source states it, lowest first.
    Where it does not, the order the entries were declared in is the order
    the code walks, so it is left alone.
    """
    ranked = [(fe.priority, position, fe) for position, fe in enumerate(files)]
    return [
        fe
        for _, _, fe in sorted(
            ranked,
            key=lambda item: (
                (0, item[0]) if item[0] is not None else (1, item[1])
            ),
        )
    ]
