"""The native model of a platform's list: its files, systems and report, and how their hashes compare."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.hashing import HASH_FIELDS, declared_hashes, parse_hash_list


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
    checked = [f for f in HASH_FIELDS if f in kinds and parse_hash_list(entry.get(f))]
    if checked and all(len(set(parse_hash_list(entry.get(f)))) == 1 for f in checked):
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
    ours = declared_hashes(checked_hashes(truth_entry) or {})
    theirs = declared_hashes(comparable(platform_entry))
    return [f for f, values in ours.items() if f in theirs and not values & theirs[f]]


def contradicts(ours: dict[str, set[str]], theirs: dict[str, set[str]]) -> bool:
    """A hash field both declared maps hold without a value in common."""
    return any(f in theirs and not values & theirs[f] for f, values in ours.items())


def shares_hash(ours: dict[str, set[str]], theirs: dict[str, set[str]]) -> bool:
    """A value in common on any hash field both declared maps hold."""
    return any(values & theirs.get(f, set()) for f, values in ours.items())


def is_label(entry: dict) -> bool:
    """A name only content-scanning cores give: no core opens that file.

    DuckStation identifies its BIOS by MD5 in a folder it scans, so
    scph1001_v20.bin names nothing a platform could check by path.
    """
    return bool(entry.get("_cores")) and "_named_by" in entry and not entry["_named_by"]


def is_placeholder(name: str) -> bool:
    return "<" in name or ">" in name or "*" in name


def _field_sets(entry: dict | None) -> dict[str, set[str]]:
    return {f: set(parse_hash_list((entry or {}).get(f))) for f in HASH_FIELDS}


def single_size(value: int | str | list[int | str]) -> int | None:
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
            return parse_hash_list((self.platform or {}).get(field_name))
        truth_values = parse_hash_list(self._checked_truth.get(field_name))
        platform_values = parse_hash_list((self.platform or {}).get(field_name))
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
            values = parse_hash_list((self.platform or {}).get(field_name))
            return values[0] if values else ""
        source = self._identity_source()
        truth_values = parse_hash_list(self._checked_truth.get(field_name))
        platform_values = parse_hash_list((self.platform or {}).get(field_name))
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
            single = single_size(entry["size"])
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
