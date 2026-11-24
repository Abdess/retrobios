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

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from core.hashing import HASH_FIELDS, declared_hashes, parse_hash_list
from model.profiles import profile_names
from model.systems import norm_system_id
from resolve.nativemodel import (
    NativeFile,
    NativeSystem,
    Report,
    checked_hashes,
    comparable,
    contradicted_hashes,
    contradicts,
    is_label,
    is_placeholder,
    shares_hash,
)

_NO_PROFILES: Mapping[str, dict] = MappingProxyType({})


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


def entry_names(entry: dict) -> set[str]:
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
    if not theirs or theirs not in entry_names(truth_entry):
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
    return shares_hash(declared_hashes(truth_entry), declared_hashes(comparable(platform_entry)))


def _contradicts(truth_entry: dict, platform_entry: dict) -> bool:
    """A hash both entries declare, without a value in common."""
    return contradicts(declared_hashes(truth_entry), declared_hashes(comparable(platform_entry)))


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


def _platform_systems(scraped_systems: dict, report: Report) -> dict[str, NativeSystem]:
    """Pass 1: the platform's own file, grouped as the platform groups it."""
    systems: dict[str, NativeSystem] = {}
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
    return systems


def _correct_matched(matched: NativeFile, truth_entry: dict, report: Report) -> None:
    """Record what the truth corrects or fills on the platform's own entry."""
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
        elif parse_hash_list(checked.get(field_name)) and not parse_hash_list(
            comparable(matched.platform).get(field_name)
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


@dataclass
class _TruthPass:
    """Pass 2: the truth applied onto the platform's grouping."""

    systems: dict[str, NativeSystem]
    report: Report
    scraped_systems: dict
    composite_zips: bool
    # Which native ids a truth system may contribute to.
    norm_to_scraped: dict[str, str] = field(init=False)
    # Every system the platform names, files or none: an addition elsewhere
    # is filed under our own slug.
    platform_ids: set[str] = field(init=False)
    native_by_norm: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        scraped_systems = self.scraped_systems
        self.norm_to_scraped = {
            norm_system_id(key): key for key in scraped_systems
        }
        self.platform_ids = {
            native_id
            for key, sys_data in scraped_systems.items()
            for native_id in (
                sys_data.get("native_id") or key,
                *(_native_id_of(key, sys_data, fe) for fe in sys_data.get("files", [])),
            )
        }
        self.native_by_norm = {}
        for system in self.systems.values():
            self.native_by_norm.setdefault(norm_system_id(system.native_id), system.native_id)

    def target_native_ids(self, truth_sid: str) -> tuple[list[str], bool]:
        """The native ids a truth system spans, and whether the first one
        is where an addition belongs without asking which core reads it."""
        scraped_systems = self.scraped_systems
        scraped_key = truth_sid if truth_sid in scraped_systems else None
        if scraped_key is None:
            scraped_key = self.norm_to_scraped.get(norm_system_id(truth_sid))
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
        direct = self.native_by_norm.get(norm_system_id(truth_sid))
        return ([direct] if direct else [truth_sid]), True

    def _files_of(self, target_ids: list[str]) -> list[NativeFile]:
        return [
            candidate
            for native_id in target_ids
            for candidate in self.systems.get(native_id, NativeSystem(native_id)).files
        ]

    def apply(self, truth_sid: str, truth_sys: dict) -> None:
        truth_files = truth_sys.get("files", [])
        if not truth_files:
            return

        target_ids, settled_id = self.target_native_ids(truth_sid)
        truth_files = [
            entry for entry in truth_files
            if (name := str(entry.get("name", "")))
            and not name.startswith("_") and not is_placeholder(name)
        ]
        candidates = [c for c in self._files_of(target_ids) if c.truth is None]
        pairs = pair_entries(truth_files, [c.platform or {} for c in candidates])
        # The cores that read what the platform files under each native id,
        # from the truth entries its declarations pair with.
        readers: dict[str, set[str]] = {}
        for t_index, index in pairs.items():
            readers.setdefault(candidates[index].native_system, set()).update(
                truth_files[t_index].get("_cores") or ()
            )
        for candidate in (c for c in self._files_of(target_ids) if c.platform is not None):
            own = str(candidate.name).casefold()
            candidate.namesakes.extend(
                entry for entry in truth_files if own in entry_names(entry)
            )

        for t_index, truth_entry in enumerate(truth_files):
            paired = pairs.get(t_index)
            if paired is not None:
                _correct_matched(candidates[paired], truth_entry, self.report)
                continue
            self._add(truth_sid, truth_entry, target_ids, settled_id, readers)

    def _add(
        self,
        truth_sid: str,
        truth_entry: dict,
        target_ids: list[str],
        settled_id: bool,
        readers: dict[str, set[str]],
    ) -> None:
        """File a truth entry the platform does not declare, when it can be."""
        name = str(truth_entry["name"])
        if is_label(truth_entry):
            self.report.labels += 1
            return
        # The emulator installs it: no user is asked to bring it.
        if truth_entry.get("bundled"):
            return

        # A file another core's entry already claimed is still the
        # platform's file, not a new one: scph101.bin, declared by two
        # PSX cores, was written into RetroDECK's manifest a second time.
        declared = [
            candidate.platform
            for candidate in self._files_of(target_ids)
            if candidate.platform is not None
        ]
        if platform_declares(truth_entry, declared):
            return

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
                self.report.unattributed.append(f"{truth_sid}/{name}")
                return
            native_id = winners[0]
        system = self.systems.get(native_id)
        if system is None:
            system = NativeSystem(native_id=native_id, from_platform=False)
            self.systems[native_id] = system
            self.report.systems_added += 1
        destination = str(
            truth_entry.get("path") or truth_entry.get("destination") or name
        )
        system.files.append(
            NativeFile(
                name=name,
                destination=destination,
                native_system=native_id,
                truth=truth_entry,
                foreign_system=native_id not in self.platform_ids,
                composite_md5=self.composite_zips and name.lower().endswith(".zip"),
            )
        )
        self.report.files_added += 1


def build_native_model(
    truth: dict,
    scraped: dict | None,
    profiles: Mapping[str, dict] = _NO_PROFILES,
) -> tuple[dict[str, NativeSystem], Report]:
    """Rebuild the platform's systems, corrected by the truth.

    `profiles` are the emulator profiles the truth was built from: they
    name the platform's runner of each addition, and none means no runner.
    Returns the systems keyed by native id, in the platform's own order
    first and truth-only additions after, plus what changed.
    """
    report = Report()
    scraped_systems = (scraped or {}).get("systems", {})
    systems = _platform_systems(scraped_systems, report)

    truth_pass = _TruthPass(
        systems, report, scraped_systems,
        (scraped or {}).get("zip_digest") == "composite",
    )
    for truth_sid in sorted(truth.get("systems", {})):
        truth_pass.apply(truth_sid, truth["systems"][truth_sid])

    # A reader takes the files in the order the list gives, so the one the
    # code looks for first is named first. Only what we add is ordered: what
    # the platform already wrote keeps the place the platform gave it.
    for system in systems.values():
        head = [fe for fe in system.files if fe.platform is not None]
        tail = [fe for fe in system.files if fe.platform is None]
        system.files = head + search_order(tail)

    _attach_runners(systems, scraped, profiles)
    return systems, report


def _attach_runners(
    systems: dict[str, NativeSystem], scraped: dict | None, profiles: Mapping[str, dict]
) -> None:
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
    from resolve.standalone import platform_launches

    declared = scraped.get("cores")
    libretro = {str(c) for c in declared} if isinstance(declared, list) else set()
    standalone = {str(c) for c in scraped.get("standalone_cores") or []}
    # The build decision reads the platform launches (own builds, twins), as the
    # pack does. The runner's name is looked up among the plain names.
    launches = platform_launches(scraped, profiles)
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
                else [(key, launches.runs_standalone(key, profiles.get(key, {})))
                      for key in sorted(fe.truth.get("_cores") or ())]
            )
            for key, as_standalone in layers:
                profile = profiles.get(key, {})
                names = profile_names(key, profile)
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
