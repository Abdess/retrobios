"""What a file list lets one choose, and the choice a command or a record asks for."""
from __future__ import annotations

import argparse
from collections.abc import Collection, Iterable
from typing import TYPE_CHECKING

from installer.console import detail
from installer.install_record import drop_recorded
from installer.lists import _pack_alone, fetch_standalone
from installer.manifest import OTHER_SYSTEMS, entry_copies
from installer.narrowing import _filter_by_target, designated_cores, narrow, narrow_to_cores, standalone_layout
from installer.offline import LOCAL
from installer.platforms import (
    SYSTEM_KEY_FILES,
    SYSTEM_SHORT_NAMES,
    _name_key,
    did_you_mean,
    display_name,
    entry_systems,
    key_file_holders,
    refuse_name,
)
from installer.refusal import Refusal
from installer.regions import WORLD_REGION, resolve_regions
from installer.remote import DEFAULT_RELEASE_REF, active_remote
from installer.text import _plural

if TYPE_CHECKING:
    from installer.games import GamesPlan


def recorded_axes(files: list[dict], omitted: Iterable[dict] = ()) -> frozenset:
    """What a file list lets --system, --core and --region narrow by: its
    systems, its cores, its regions. A list from an older release records
    none. The MinUI family's records cores and regions and no system: all
    three were refused on it, by a remedy that fetched the same list."""
    entries = [*files, *omitted]
    systems = any("systems" in entry for entry in entries)
    if not systems and not any("regions" in entry for entry in entries):
        # Systems and regions came in one release: a list with neither is
        # older, its cores read by nothing that narrows.
        return frozenset()
    # A current list records the regions of the files a region selects, and
    # none when it has no such file: --region then keeps every file, as the
    # pack built with it does.
    axes = {"regions", *(["systems"] if systems else [])}
    if any(copy.get("cores") for entry in files
           for copy in entry_copies(entry)):
        axes.add("cores")
    return frozenset(axes)


def records_selection(files: list[dict]) -> bool:
    """Whether a manifest records anything narrowing reads. Older ones do not."""
    return bool(recorded_axes(files))


def available_choices(files: list[dict], omitted: list[dict]) -> dict[str, list[str]]:
    """The systems, cores and regions a manifest lets one narrow to."""
    systems = {s for e in files + omitted for s in entry_systems(e)}
    ordered = sorted(systems)
    if any(not entry_systems(f) for f in files):
        ordered.append(OTHER_SYSTEMS)
    cores = {
        c for f in files
        for copy in entry_copies(f)
        for c in (copy.get("cores") or [])
    }
    regions = {
        r for e in files + omitted for r in (e.get("regions") or [])
        if r != WORLD_REGION
    }
    return {
        "systems": ordered,
        "cores": sorted(cores),
        "regions": sorted(regions),
    }


def choosable_cores(files: list[dict], omitted: list[dict],
                    systems: Collection[str] = ()) -> list[str]:
    """The cores a choice is made among, for the files a run keeps once
    the save entries it cannot place and the game data --no-game-data cuts
    are left out, of the systems chosen (every system for none). Cores on
    the screen and c in line mode list these and count "N of M" out of
    them: the screen listed the whole file list's 189 where the run
    accepted 181."""
    if systems:
        files, omitted = narrow(files, omitted, list(systems), [], [])
    return available_choices(files, omitted)["cores"]


def core_files(files: list[dict], core: str) -> list[dict]:
    """The files one core adds to the platform's own: what line mode's
    Cores question and the screen's Cores rows size."""
    return _filter_by_target([entry for entry in files if entry.get("cores") is not None],
                             [core])


def resolve_choices(
    values: list[str], known: list[str], label: str,
    aliases: dict[str, str] | None = None,
    holders: dict[str, list[str]] | None = None,
) -> list[str]:
    """Names given on the command line, matched without regard to case.

    Each value is one name or a comma-separated list. A whole value that is
    itself a name wins over splitting it: Recalbox names one system
    `msx1,msx2,msxturbor`. An unknown name is refused, never ignored, since
    carrying on would install something other than what was asked.
    aliases maps another name of a known one to it, as Batocera's `psx`
    stands for sony-playstation. A known name always wins over an alias.
    holders maps a system the list files under other ids to those ids
    (key_file_holders): an unknown name for it is answered with them.
    """
    aliases = {alias: name for alias, name in (aliases or {}).items() if name in known}
    by_lower = {name.lower(): name for name in known}
    for alias, name in aliases.items():
        by_lower.setdefault(alias.lower(), name)
    # Spelled as the site writes it (Sony PlayStation), a name is still one
    # name when no other one reads the same once case and spacing go.
    by_key: dict[str, str | None] = {}
    for name in known:
        key = _name_key(name)
        by_key[key] = None if key in by_key else name
    for alias, name in aliases.items():
        by_key.setdefault(_name_key(alias), name)
    chosen: list[str] = []
    unknown: list[str] = []
    for value in values:
        value = value.strip()
        tokens = [value] if value.lower() in by_lower else value.split(",")
        for token in (t.strip() for t in tokens):
            if not token:
                continue
            picked = by_lower.get(token.lower()) or by_key.get(_name_key(token))
            if picked is None:
                unknown.append(token)
            elif picked not in chosen:
                chosen.append(picked)
    if unknown:
        if not known:
            raise ValueError(f"unknown {label}: {', '.join(unknown)}. This list records none.")
        listing = {"system": "--list-systems", "emulator": "--list-emulators"}.get(
            label, "--list-cores")
        hints, inside_from = aliases, 4
        held = holders or {}
        stands_for: dict[str, str] = {}
        notes = ""
        if label == "system":
            # gba is the end of nintendo-gba: three letters are enough here.
            hints = {**{short: name for short, name in SYSTEM_SHORT_NAMES.items()
                        if name in known}, **aliases}
            inside_from = 3
            stands_for = {_name_key(system): system for system in held}
            for short, name in SYSTEM_SHORT_NAMES.items():
                if name in held:
                    stands_for.setdefault(_name_key(short), name)
            named = dict.fromkeys(
                stands_for[_name_key(token)] for token in unknown
                if _name_key(token) in stands_for)
            notes = "".join(
                f"This list files {SYSTEM_KEY_FILES[system]} under "
                f"{', '.join(held[system])}. " for system in named)
        meant = {key: held[system] for key, system in stands_for.items()}
        raise ValueError(
            f"unknown {label}: {', '.join(unknown)}. {notes}"
            f"{did_you_mean(unknown, known, listing, hints, inside_from, meant)}"
        )
    if values and not chosen:
        raise ValueError(f"--{label} needs at least one name")
    return chosen


def resolve_systems(values: list[str], manifest: dict | None, files: list[dict],
                    omitted: list[dict]) -> list[str]:
    """The systems --system names, for an install and a removal alike: the
    list's ids, the platform's own names and the site's titles. --remove
    took the ids alone, and refused the psx that installed the files."""
    return resolve_choices(values, available_choices(files, omitted)["systems"], "system",
                           system_aliases(manifest), key_file_holders(files, omitted))


def system_ids(names: Iterable[str], manifest: dict | None, files: list[dict],
               omitted: list[dict]) -> dict[str, str]:
    """Each of names that --system takes, with the system id it stands for:
    a record keeps the psx typed at the install."""
    known = available_choices(files, omitted)["systems"]
    aliases, holders = system_aliases(manifest), key_file_holders(files, omitted)
    ids: dict[str, str] = {}
    for name in names:
        try:
            picked = resolve_choices([name], known, "system", aliases, holders)
        except ValueError:
            continue
        if len(picked) == 1:
            ids[name] = picked[0]
    return ids


def parse_selection(text: str, count: int, ordered: bool = False) -> list[int]:
    """Numbers typed at a prompt: `3`, `1,4`, `2-5`, or `all`, 1-based.

    Returned sorted, or in the typed order when the order is a priority.
    """
    if text.strip().lower() in ("all", "*"):
        return list(range(1, count + 1))
    chosen: list[int] = []
    for token in (t.strip() for t in text.split(",")):
        if not token:
            continue
        low, sep, high = token.partition("-")
        try:
            start = int(low)
            end = int(high) if sep else start
        except ValueError:
            raise ValueError(f"not a number or range: {token}") from None
        if start > end or start < 1 or end > count:
            raise ValueError(f"out of range: {token} (1-{count})")
        for number in range(start, end + 1):
            if number not in chosen:
                chosen.append(number)
    return chosen if ordered else sorted(chosen)


def system_aliases(manifest: dict | None) -> dict[str, str]:
    """The platform's own names for its systems, then the titles the site
    and the installer print (SNK Neo Geo CD), each with the system id.

    A title two systems share names neither, and the platform's own name
    wins over a title spelled the same.
    """
    aliases = {
        alias: system
        for system, names in ((manifest or {}).get("system_names") or {}).items()
        for alias in names
    }
    taken = {_name_key(alias) for alias in aliases}
    titles = (manifest or {}).get("system_titles") or {}
    counts: dict[str, int] = {}
    for title in titles.values():
        counts[_name_key(title)] = counts.get(_name_key(title), 0) + 1
    for system, title in titles.items():
        key = _name_key(title)
        if key and counts[key] == 1 and key not in taken:
            aliases[title] = system
    return aliases


def emulator_names(manifest: dict, files: list[dict], omitted: list[dict]) -> dict[str, str]:
    """Every name --emulator accepts, with the profile each one stands for.

    A profile answers to its own name and to the names its core is built
    under (core_names: beetle_psx and mednafen_psx). A core named by a file
    and by no profile stands for itself.
    """
    names = {core: core for core in available_choices(files, omitted)["cores"]}
    for profile, aliases in (manifest.get("core_names") or {}).items():
        names[profile] = profile
        for alias in aliases:
            names.setdefault(alias, profile)
    return names


GAMES_REQUIRED_WORDS = "only what the games need to start"


class GamesChoice:
    """The line menu's choice of what the games of the card need, all of it
    or only what they cannot start without (required)."""

    def __init__(self, plan: GamesPlan, required: bool = False) -> None:
        self.plan = plan
        self.required = required

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, GamesChoice) and other.plan is self.plan
                and other.required == self.required)

    def __hash__(self) -> int:
        return hash((id(self.plan), self.required))

    def apply(self, files: list[dict], omitted: list[dict]) -> tuple[list[dict], list[dict]]:
        return self.plan.apply(files, omitted, self.required)

    def flags(self) -> list[tuple[str, str | None]]:
        folder = None if self.plan.card else str(self.plan.root)
        return [("--for-games", folder), *([("--required-only", None)] if self.required else [])]

    def words(self) -> str:
        """What the choice keeps, after a comma on the menu's head."""
        named = f"for the {_plural(len(self.plan.games), 'game')} {self.plan.where()}"
        return f"{named}, {GAMES_REQUIRED_WORDS}" if self.required else named


def _older_list_advice(plat: str = "") -> str:
    """How to reach a file list that records what an option needs.

    A list without the fields comes from an older release. Pinned with
    RETROBIOS_REF, as the docs suggest for reproducibility, "a newer one"
    meant unsetting the variable, and nothing said so. A pack's own list is
    the pack's: the one-line installer does not change it, and a current
    pack was said to come from an older release.
    """
    if _pack_alone(plat) and LOCAL.pack is not None:
        return (f"  The list in {LOCAL.pack.name} does not record it: add --manifest FILE, "
                f"a copy of install/{plat or '<platform>'}.json, or run without the option.")
    ref = active_remote().ref
    if ref != DEFAULT_RELEASE_REF:
        return (f"  RETROBIOS_REF={ref} selects file lists published before "
                "this option existed: unset RETROBIOS_REF to use the current ones, "
                "or run without the option.")
    return ("  The file list comes from an older release: run the one-line "
            "installer again to fetch the current one.")


def _narrowing_advice(plat: str, axis: str, flag: str, recorded: frozenset,
                      pack_alone: bool) -> str:
    """What to do when a list or a pack records no axis: only a remedy
    that changes the outcome. The pack's remedy named install/minui.json,
    refused the same way, and the list's fetched the same list again."""
    works = [name for name, field in (("--system", "systems"), ("--core", "cores"),
                                      ("--region", "regions")) if field in recorded]
    rest = f"Run it without {flag}" + (f", or narrow with {' and '.join(works)}"
                                       if works else "") + "."
    if pack_alone:
        listed = LOCAL.pack.list_records if LOCAL.pack is not None else None
        if listed is not None and axis not in listed:
            # The pack says its platform's own list lacks the axis too.
            return f"  {display_name(plat)}'s own file list records no {axis} either. {rest}"
        when = "which records them" if listed is not None else f"when that list records {axis}"
        return f"  Add --manifest FILE, a copy of install/{plat}.json, {when}. {rest}"
    if recorded:
        # A current list: the platform has no such axis.
        return f"  {rest}"
    return _older_list_advice(plat)


def _narrow_to_emulators(
    names: list[str], manifest: dict, plat: str,
    files: list[dict], omitted: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Keep what the named emulators read, as the pack built for them.

    An emulator page offers this as one command, so a name the platform
    does not run is refused rather than read as nothing to install.
    """
    if "system_cores" not in manifest:
        raise Refusal("option", "not_recorded", plat,
                      f"Error: the {plat} file list does not say which emulators read "
                      "which systems, which --emulator needs.", _older_list_advice(plat))
    known = sorted(emulator_names(manifest, files, omitted))
    try:
        chosen = resolve_choices(names, known, "emulator")
    except ValueError as exc:
        refuse_name(plat, f"Error: {plat}: {exc}")
    before = len(files)
    files, omitted = narrow_to_cores(manifest, chosen, files, omitted)
    # A whole-platform install keeps the platform's files of a system no
    # core is mapped to. Here only the named emulators' systems are wanted.
    cores = designated_cores(manifest, chosen)
    reached = {
        system for system, readers in (manifest.get("system_cores") or {}).items()
        if cores.intersection(readers)
    }

    def theirs(entry: dict) -> bool:
        return entry.get("cores") is not None or bool(reached.intersection(entry_systems(entry)))

    files = [entry for entry in files if theirs(entry)]
    omitted = [entry for entry in omitted if theirs(entry)]
    print(f"  Narrowed {before} to {len(files)} files to {', '.join(chosen)}")
    return files, omitted


def _standalone_builds(
    values: list[str], names: dict[str, str], manifest: dict, plat: str,
    files: list[dict], omitted: list[dict],
) -> tuple[list[dict], list[dict]]:
    """--emulator with --standalone: each emulator's standalone build in
    place of the files its core reads. An emulator with no standalone
    build is refused, as `generate_pack.py --standalone` refuses it."""
    if "standalone_builds" not in manifest:
        raise Refusal("option", "not_recorded", plat,
                      f"Error: the {plat} file list does not say which emulators have a "
                      "standalone build, which --standalone needs.", _older_list_advice(plat))
    profiles = sorted({names[name] for name in resolve_choices(values, sorted(names),
                                                                "emulator")})
    lacking = [p for p in profiles if p not in manifest["standalone_builds"]]
    if lacking:
        refuse_name(plat, f"Error: {', '.join(lacking)} has no standalone build: run "
                    "again without --standalone.")
    before = len(files)
    files, omitted = standalone_layout(manifest, fetch_standalone(plat, manifest), profiles,
                                       files, omitted)
    detail(f"  The standalone {'builds' if len(profiles) > 1 else 'build'}: "
           f"{before} to {len(files)} files")
    return files, omitted


def _known_names(values: list[str] | None, known: list[str], label: str,
                 aliases: dict[str, str] | None = None) -> list[str]:
    """The names of values that resolve against known, the others left out."""
    kept = []
    for value in values or []:
        try:
            resolve_choices([value], known, label, aliases)
        except ValueError:
            continue
        kept.append(value)
    return kept


def _recorded_names(args: argparse.Namespace, plat: str, flag: str, known: list[str],
                    aliases: dict[str, str] | None = None) -> None:
    """A recorded --system, --core or --emulator kept to the names the list
    still holds, the others left out in one line."""
    name = flag[2:].replace("-", "_")
    values = list(getattr(args, name) or [])
    kept = _known_names(values, known, flag[2:], aliases)
    if kept != values:
        gone = ", ".join(value for value in values if value not in kept)
        drop_recorded(args, plat, flag, f"{gone} no longer on the list", kept)


def _recorded_emulators(args: argparse.Namespace, plat: str, manifest: dict,
                        files: list[dict], omitted: list[dict]) -> None:
    """A recorded --emulator that cannot narrow this list, left out."""
    if "system_cores" not in manifest:
        drop_recorded(args, plat, "--emulator", "the list does not say which emulators "
                      "read which systems")
        return
    _recorded_names(args, plat, "--emulator", sorted(emulator_names(manifest, files, omitted)))


def _recorded_regions(args: argparse.Namespace, plat: str) -> None:
    """A recorded --region kept to the regions this installer knows."""
    values = list(args.region or [])
    kept = []
    for value in values:
        try:
            resolve_regions([value])
        except ValueError:
            continue
        kept.append(value)
    if kept != values:
        drop_recorded(args, plat, "--region", "a region this installer does not know", kept)


def _requested_narrowing(
    args: argparse.Namespace, plat: str, files: list[dict], omitted: list[dict],
    manifest: dict | None = None,
) -> tuple[list[str], list[str], list[str]] | None:
    """The systems, cores and regions named on the command line, checked."""
    if not (args.system or args.core or args.region):
        return None
    pack_alone = _pack_alone(plat)
    recorded = recorded_axes(files, omitted)
    if pack_alone:
        # A pack records the systems of its files, not their cores or
        # regions: either filter would keep everything, and is refused.
        recorded = recorded & {"systems"}
    asked = [(flag, axis) for flag, given, axis in (
        ("--system", args.system, "systems"), ("--core", args.core, "cores"),
        ("--region", args.region, "regions")) if given]
    if getattr(args, "from_record", False):
        # A recorded option that cannot narrow this list is left out: nobody
        # typed it, and every run without options would stop on it.
        for flag, axis in asked:
            if axis not in recorded:
                drop_recorded(args, plat, flag, f"the list records no {axis}")
        asked = [(flag, axis) for flag, axis in asked if axis in recorded]
        _recorded_regions(args, plat)
        choices = available_choices(files, omitted)
        if args.system:
            _recorded_names(args, plat, "--system", choices["systems"],
                            system_aliases(manifest))
        if args.core:
            _recorded_names(args, plat, "--core", choices["cores"])
        if not (args.system or args.core or args.region):
            return None
    for flag, axis in asked:
        if axis in recorded:
            continue
        # Without the field, a filter would match nothing and install
        # everything: refused rather than ignored, by the axis the list
        # lacks, with what works on it.
        source = (LOCAL.pack.name if pack_alone and LOCAL.pack is not None
                  else f"the {plat} file list")
        raise Refusal("option", "not_recorded", plat,
                      f"Error: {source} records no {axis}, so {flag} cannot narrow it.",
                      _narrowing_advice(plat, axis, flag, recorded, pack_alone))
    choices = available_choices(files, omitted)
    try:
        systems = resolve_systems(args.system or [], manifest, files, omitted)
        cores = resolve_choices(args.core or [], choices["cores"], "core")
        regions = resolve_regions(args.region or [])
    except ValueError as exc:
        refuse_name(plat, f"Error: {plat}: {exc}")
    return systems, cores, regions
