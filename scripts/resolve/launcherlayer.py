"""The platform's launcher layer, read by verify and by the pack builder.

A platform's own launch code often decides which name a file is read under.
Batocera's DuckStation generator tries 22 names per region and keeps the
first it finds, RetroBat's ares launcher writes the LaserActive image it
finds into ares's settings. The platform scraper records that code under
``launchers:`` and this module turns the records into places: a set of
destinations, relative to the directory core files go to, any one of which
the launcher reads for one purpose.

Two consequences follow, both computed here once for every reader. A core
file the launcher would not read because another name of the same place is
held is not missing on that platform. A place nothing fills yet receives,
under the launcher's name, a file the core accepts by content.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from core.hashing import HASH_FIELDS, declared_hashes
from core.paths import sanitize_pack_path
from model.database import record_at
from model.launcherrecords import emulator_names
from model.profiles import lists_files, profile_names
from resolve.content import name_match_size_ok
from resolve.launcherplaces import (
    LauncherPlace,
    catalogued_model_files,
    launcher_places,
    set_by,
    setting_readers,
    suffixed_stem,
)
from resolve.localfile import resolve_local_file


def held_record(report: dict, db: dict) -> dict | None:
    """The database record of the file the collection holds for a report entry."""
    local, status = resolve_local_file(report, db, dest_hint=report.get("path") or "")
    if local is None or status in ("not_found", "hash_mismatch"):
        return None
    return record_at(db, local)


def _hashes(entry: dict) -> dict[str, set[str]]:
    expected = entry.get("expected") or {}
    return declared_hashes({f: entry.get(f) or expected.get(f) for f in HASH_FIELDS})


def accepts(entry: dict, record: dict) -> bool:
    """Whether a core entry takes the database file ``record`` by its content."""
    hashes = _hashes(entry)
    if not hashes:
        return False
    return any(
        str(record.get(field, "")).lower() in values
        for field, values in hashes.items()
    )


@dataclass
class _Candidate:
    """A core entry one launcher place stands for, and how it was matched."""

    entry: dict
    names: set[str]
    by_content: bool
    # Matched by the size the code checks, the entry naming no hash.
    by_shape: bool = False
    # Matched through the setting the launcher writes or the name it extends.
    by_setting_or_stem: bool = False


class LauncherLayer:
    """The launcher places of one platform matched to the cores it runs.

    ``declared`` holds each destination the platform declares, relative to
    the directory core files go to, case kept.
    """

    def __init__(
        self,
        config: dict,
        profiles: dict,
        relevant: Iterable[str],
        db: dict,
        declared: Iterable[str],
    ) -> None:
        self.places = launcher_places(config, profiles)
        self.declared = set(declared)
        self.declared_folded = {d.lower() for d in self.declared}
        self.declared_names = {d.rsplit("/", 1)[-1] for d in self.declared}
        self.declared_names_folded = {n.lower() for n in self.declared_names}
        by_name = db.get("indexes", {}).get("by_name", {})
        self._by_name = by_name
        self._by_name_folded: dict[str, list[str]] = {}
        for name, sha1s in by_name.items():
            self._by_name_folded.setdefault(name.lower(), []).extend(sha1s)
        self._files = db.get("files", {})
        self._owners: dict[tuple[str, bool], list[LauncherPlace]] = {}
        self._unoffered: dict[tuple[str, bool], list[tuple[dict, dict]]] = {}
        relevant = set(relevant)
        for place in self.places:
            standalone = place.build == "standalone"
            owners = {
                key
                for emulator in emulator_names(place.emulator)
                for key in self._profiles_named(emulator, profiles, relevant)
            }
            # RetroDECK names its frontend, retroarch, and the core option it
            # writes, pcsx2_bios, names the core: a libretro core option
            # belongs to a libretro core.
            if place.build == "libretro" and place.kind == "core_option":
                owners = {k for k in owners if "libretro" in str(profiles[k].get("type") or "")}
            if not owners:
                owners = set(setting_readers(place.passes_to, profiles, relevant))
            for key in sorted(owners):
                self._owners.setdefault((key, standalone), []).append(place)
                # The report never offers a placeholder, which stands for every
                # file a scan finds, nor an entry the platform's list settles
                # (AmberELEC declares kick34005.A500): the launcher still reads
                # its file under its own name.
                self._unoffered.setdefault((key, standalone), [
                    (entry, _placeholder_report(key, profiles[key], entry))
                    for entry in profiles[key].get("files") or []
                ])
        self._db = db
        self._declared_elsewhere: set[tuple[str, bool, str, str]] = set()

    def declared_elsewhere(self, emulator: str, standalone: bool, entry: dict) -> None:
        """Record a core entry the platform's list settles under another
        name. A launcher opening the entry's own name finds nothing there:
        RetroPie lists KS 1.3 as kick34005.A500, and its fs-uae launcher
        passes $biosdir/kick13.rom. A name the list holds somewhere is
        copied to the launcher's place from that declaration."""
        name = str(entry.get("name", ""))
        if name.rsplit("/", 1)[-1].lower() in self.declared_names_folded:
            return
        self._declared_elsewhere.add((emulator, standalone, name, str(entry.get("path") or "")))

    @staticmethod
    def _profiles_named(name: str, profiles: dict, relevant: set[str]) -> list[str]:
        """The profiles a platform's emulator name designates, among those it runs."""
        return sorted(
            key for key in relevant
            if (profile := profiles.get(key)) is not None
            and lists_files(profile)
            and name in profile_names(key, profile)
        )

    def __bool__(self) -> bool:
        return bool(self._owners)

    def places_for(self, emulator: str, standalone: bool) -> list[LauncherPlace]:
        return self._owners.get((emulator, standalone), [])

    def files_named(self, place: LauncherPlace, name: str) -> list[dict]:
        """The database files carrying a name, in the place's case rule."""
        if place.case_insensitive:
            sha1s = self._by_name_folded.get(name.lower(), [])
        else:
            sha1s = self._by_name.get(name, [])
        return [self._files[s] for s in dict.fromkeys(sha1s) if s in self._files]

    def match(self, place: LauncherPlace, entry: dict) -> _Candidate | None:
        """How a core entry belongs to a place: by a name it is read under, or by content."""
        basenames = place.basenames()
        own = {
            place.fold(str(n).rsplit("/", 1)[-1])
            for n in (entry.get("name", ""), *(entry.get("aliases") or []))
            if n
        }
        names = own & basenames
        if names:
            return _Candidate(entry, names, False)
        # RetroPie runs sdl2trs with `-romfile4p $biosdir/level4p.rom`: the
        # file under that name is the one the romfile4p slot reads.
        if set_by(entry, place.passes_to):
            return _Candidate(entry, basenames, False, by_setting_or_stem=True)
        if place.kind == "fixed_name":
            stems = {
                base for base in basenames
                if (stem := suffixed_stem(base)) is not None and place.fold(stem) in own
            }
            if stems:
                return _Candidate(entry, stems, False, by_setting_or_stem=True)
        content = {
            place.fold(path.rsplit("/", 1)[-1])
            for path in place.paths
            if any(
                accepts(entry, record)
                for record in self.files_named(place, path.rsplit("/", 1)[-1])
            )
        }
        if content:
            return _Candidate(entry, content, True)
        # A hashless entry the code checks by size: EmuDeck passes
        # Complex_4627v1.03.bin as xemu's flash ROM, and xemu's entry
        # Complex_4627.bin states only the sizes it maps.
        checks = entry.get("validation") or []
        sized = any(entry.get(k) for k in ("size", "min_size", "max_size"))
        if not _hashes(entry) and sized and "size" in checks:
            shaped = {
                place.fold(path.rsplit("/", 1)[-1])
                for path in place.paths
                if any(
                    name_match_size_ok(entry, record.get("size"))
                    for record in self.files_named(place, path.rsplit("/", 1)[-1])
                )
            }
            if shaped:
                return _Candidate(entry, shaped, False, by_shape=True)
        return None

    def platform_holds(self, place: LauncherPlace) -> bool:
        """Whether the platform's own list declares a file the place reads."""
        if place.anchored:
            pool = self.declared_folded if place.case_insensitive else self.declared
            return any(place.fold(path) in pool for path in place.paths)
        pool = self.declared_names_folded if place.case_insensitive else self.declared_names
        return bool(place.basenames() & pool)

    def _add_unoffered(
        self,
        by_layout: dict[tuple[str, bool], list[tuple[dict, dict]]],
        offered: set[int],
        resolve_held: Callable[[dict], dict | None],
    ) -> None:
        """The entries the report left out, each answering only through a
        launcher's setting or extended name."""
        for layout, members in self._unoffered.items():
            for entry, report in members:
                if id(entry) in offered:
                    continue
                if "<" not in str(entry.get("name", "")):
                    report["in_repo"] = resolve_held(report) is not None
                report["unoffered"] = True
                if (*layout, str(entry.get("name", "")),
                        str(entry.get("path") or "")) in self._declared_elsewhere:
                    report["declared_elsewhere"] = True
                by_layout.setdefault(layout, []).append((entry, report))

    def settle(
        self,
        candidates: list[tuple[str, bool, dict, dict]],
        resolve_held: Callable[[dict], dict | None],
    ) -> tuple[list[dict], set[int]]:
        """What the launcher layer adds to the report and what it settles.

        ``candidates`` holds (profile, standalone, profile entry, report
        entry) for every core entry the report considered. ``resolve_held``
        returns the database record of the file the collection holds for a
        report entry, None when it holds none.

        Returns the report entries to add, one per place nothing filled that
        a held file the core accepts can fill under the launcher's name, and
        the ids of the report entries the filled places settle.
        """
        added: list[dict] = []
        settled: set[int] = set()
        # Destinations the report already fills with a held file, whichever
        # core asked for it: the pack puts a file there either way.
        reported_at: dict[str, dict] = {}
        for _emulator, _standalone, _entry, report in candidates:
            # A file the layout reads outside the BIOS tree fills no
            # destination of it.
            if report.get("in_repo") and not report.get("unplaced"):
                destination = sanitize_pack_path(report.get("path") or report.get("name", ""))
                reported_at.setdefault(destination, report)
        by_layout: dict[tuple[str, bool], list[tuple[dict, dict]]] = {}
        for emulator, standalone, entry, report in candidates:
            by_layout.setdefault((emulator, standalone), []).append((entry, report))
        self._add_unoffered(
            by_layout, {id(entry) for _e, _s, entry, _r in candidates}, resolve_held,
        )
        placed: set[str] = set()
        for (emulator, standalone), members in sorted(by_layout.items()):
            for place in self.places_for(emulator, standalone):
                # An entry the report left out answers only through the
                # setting or the extended name: by its own name it was left
                # out for a reason (a region variant, a settled duplicate).
                # One the platform settles under another name still answers
                # by its own: the place reads a name the list does not hold.
                matched = [
                    (candidate, report)
                    for entry, report in members
                    if (candidate := self.match(place, entry)) is not None
                    and (candidate.by_setting_or_stem or not report.get("unoffered")
                         or report.get("declared_elsewhere"))
                ]
                # A size names one entry only when no other of the core's
                # entries takes that size too.
                if sum(c.by_shape for c, _ in matched) > 1:
                    matched = [(c, r) for c, r in matched if not c.by_shape]
                if not matched:
                    continue
                filled = self._fill(place, matched, reported_at, resolve_held, placed)
                if filled is None:
                    continue
                if isinstance(filled, dict):
                    added.append(filled)
                # The launcher hands the emulator that file from the BIOS
                # tree: read outside it no more.
                settled.update(id(report) for _c, report in matched if report.get("unplaced"))
                if place.stands_for_default:
                    # The emulator opens the launcher's file instead of its
                    # own name, so a copy under that name is read by nobody:
                    # EmuDeck passes Complex_4627v1.03.bin to xemu, which then
                    # never opens Complex_4627.bin. A held file sitting on one
                    # of the place's own paths is what fills it.
                    own = {place.fold(p) for p in place.paths}
                    settled.update(
                        id(report) for _candidate, report in matched
                        if not report.get("in_repo")
                        or place.fold(sanitize_pack_path(
                            report.get("path") or report.get("name", "")
                        )) not in own
                    )
        return added, settled

    def _fill(
        self,
        place: LauncherPlace,
        matched: list[tuple[_Candidate, dict]],
        reported_at: dict[str, dict],
        resolve_held: Callable[[dict], dict | None],
        placed: set[str],
    ) -> dict | bool | None:
        """True when the place is filled already, a new report entry when one fills it."""
        if self.platform_holds(place):
            return True
        folded_reported = {place.fold(dest): r for dest, r in reported_at.items()}
        for path in place.paths:
            name = path.rsplit("/", 1)[-1]
            key = place.fold(name)
            if place.anchored:
                if place.fold(path) in folded_reported:
                    return True
            elif any(
                key == place.fold(r.get("name", "")) or key == place.fold(dest.rsplit("/", 1)[-1])
                for dest, r in folded_reported.items()
            ):
                return True
            if not place.anchored:
                # A setting holds a name the core resolves in the directory
                # of the entry read from it: LRPS2 joins pcsx2_bios under
                # pcsx2/bios.
                setting = [
                    (candidate, report) for candidate, report in matched
                    if set_by(candidate.entry, place.passes_to)
                ]
                directory = next(
                    (
                        str(c.entry.get("path") or "").rpartition("/")[0]
                        for c, _report in setting
                        if "/" in str(c.entry.get("path") or "")
                    ),
                    None,
                )
                if directory is None:
                    continue
                path = f"{directory}/{name}"
                if place.fold(path) in folded_reported:
                    return True
                source = self._content_for(place, name, key, setting, resolve_held)
                if source is None or place.fold(path) in placed:
                    continue
                placed.add(place.fold(path))
                return _launcher_entry(source[0], name, path, source[1], place)
            # The emulator as this platform installs it brings the file: the
            # place is filled, nothing is packed (ROCKNIX's xemu hdd image).
            if any(key in candidate.names and report.get("bundled")
                   for candidate, report in matched):
                return True
            source = self._content_for(place, name, key, matched, resolve_held)
            if source is None:
                continue
            report, record = source
            if place.fold(path) in placed:
                return True
            placed.add(place.fold(path))
            return _launcher_entry(report, name, path, record, place)
        return None

    def _content_for(
        self,
        place: LauncherPlace,
        name: str,
        key: str,
        matched: list[tuple[_Candidate, dict]],
        resolve_held: Callable[[dict], dict | None],
    ) -> tuple[dict, dict] | None:
        """A held file the core accepts for one launcher name, and its entry.

        The file the database knows under that name comes first when the
        core accepts it: by content when the entry pins one, by name and
        size when the entry reads it under that name. Otherwise the file the
        collection holds for an entry read under that name.
        """
        for candidate, report in matched:
            if key not in candidate.names:
                continue
            for record in self.files_named(place, name):
                if accepts(candidate.entry, record) or (
                    not candidate.by_content
                    and not _hashes(candidate.entry)
                    and name_match_size_ok(candidate.entry, record.get("size"))
                ):
                    return report, record
        for candidate, report in matched:
            if key not in candidate.names or candidate.by_content:
                continue
            if not report.get("in_repo"):
                continue
            held = resolve_held(report)
            if held is not None:
                return report, held
        for candidate, report in matched:
            if key not in candidate.names or not set_by(candidate.entry, place.passes_to):
                continue
            for record in catalogued_model_files(name, self._db):
                if name_match_size_ok(candidate.entry, record.get("size")):
                    return report, record
        return None


def _placeholder_report(key: str, profile: dict, entry: dict) -> dict:
    """The report entry of an entry the gap report never builds."""
    identity = {
        field: entry[field]
        for field in ("aliases", "md5", "sha1", "sha256", "crc32", "size", "min_size", "max_size")
        if entry.get(field) is not None
    }
    return {
        **identity,
        "profile": key,
        "emulator": profile.get("emulator", key),
        "name": entry.get("name", ""),
        "path": entry.get("path") or entry.get("name", ""),
        "system": entry.get("system"),
        "systems": profile.get("systems"),
        "required": entry.get("required", False),
        "category": entry.get("category"),
        "in_repo": False,
    }


def _launcher_entry(
    report: dict, name: str, path: str, record: dict, place: LauncherPlace
) -> dict:
    """The report entry asking for a file under the name a launcher opens."""
    entry = {
        key: report.get(key)
        for key in (
            "profile", "emulator", "systems", "system", "region", "selection_slot",
            "required", "hle_fallback", "category",
        )
    }
    entry.update(
        name=name,
        path=path,
        bundled=False,
        in_repo=True,
        note="",
        checks=[],
        source_ref=None,
        expected={},
        sha1=record.get("sha1"),
        md5=record.get("md5"),
        launcher=place.source_ref,
        launcher_of=report.get("name", ""),
    )
    return entry
