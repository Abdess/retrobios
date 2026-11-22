"""The start-with list atop a console: which file to get first."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from model.collection import SECTION_LABELS
from packs.consumers import FileConsumers
from sitegen import markup
from sitegen.cards import ROMSET_FAQ, emulator_display, romset_releases
from sitegen.consolecards import (
    Card,
    START_WITH_NAMES,
    NO_PRIORITY,
    add_name,
    card_rank,
    entries_by_section,
    entry_systems,
    reading_pairs,
    region_order,
    setup_name,
    visible_name,
    without_files,
)
from core.text import series
from sitegen.emulatorcards import region_words
from sitegen.install import comes_with_app
from sitegen.render import card_anchor, code_span, count_text, console_anchor


class _StartGroup:
    """What one system of a section asks for."""

    def __init__(self) -> None:
        self.by_region: dict[str, list[str]] = {}
        self.plain: list[str] = []
        # Files an emulator reads when present and replaces when absent.
        self.optional: list[str] = []
        self.emulators: list[str] = []
        # Each file an emulator requires, by its visible name, with the
        # emulators requiring it and the name as the line writes it.
        self.requires: dict[str, set[str]] = {}
        self.written: dict[str, str] = {}
        # Visible name -> the sha1 of the file it names.
        self.sha1s: dict[str, str] = {}
        # Emulators that replace a missing file with their own code.
        self.hle: set[str] = set()
        # Files an emulator reads when present and runs the same without.
        self.extra: list[str] = []
        # By line (a region, "" for every region): visible name -> the
        # emulators requiring that file for the line. Three Mega CD BIOS,
        # one per region, share the name cd_bios.rom.
        self.line_readers: dict[str, dict[str, set[str]]] = {}
        # (line, visible name, emulator) -> the name the emulator reads.
        self.read_as: dict[tuple[str, str, str], str] = {}
        # (line, visible name) -> the file name its card shows.
        self.card_names: dict[tuple[str, str], str] = {}
        # (line, visible name) of the files most of whose readers read
        # them beside another one they require.
        self.extras: set[tuple[str, str]] = set()

    def require(self, name: str, emulator: str) -> None:
        self.written.setdefault(visible_name(name), name)
        self.requires.setdefault(visible_name(name), set()).add(emulator)

    def read_for(self, line: str, name: str, emulator: str, read: str, card: str) -> None:
        """Record that ``emulator`` requires ``name`` for ``line``, under
        the name ``read``, its card titled ``card``."""
        visible = visible_name(name)
        self.line_readers.setdefault(line, {}).setdefault(visible, set()).add(emulator)
        self.read_as.setdefault((line, visible, emulator), read)
        self.card_names.setdefault((line, visible), card)

    def absorb(self, other: _StartGroup) -> None:
        for region, names in other.by_region.items():
            for name in names:
                add_name(self.by_region.setdefault(region, []), name)
        for mine, theirs in ((self.plain, other.plain), (self.optional, other.optional),
                             (self.extra, other.extra), (self.emulators, other.emulators)):
            for name in theirs:
                add_name(mine, name)
        for visible, emulators in other.requires.items():
            self.written.setdefault(visible, other.written[visible])
            self.requires.setdefault(visible, set()).update(emulators)
        for visible, sha1 in other.sha1s.items():
            self.sha1s.setdefault(visible, sha1)
        self.hle.update(other.hle)
        for line, readers in other.line_readers.items():
            for visible, emulators in readers.items():
                self.line_readers.setdefault(line, {}).setdefault(visible, set()).update(emulators)
        for key, value in other.read_as.items():
            self.read_as.setdefault(key, value)
        for card_key, card_name in other.card_names.items():
            self.card_names.setdefault(card_key, card_name)
        self.extras |= other.extras

    def requirers(self) -> set[str]:
        return set().union(*self.requires.values()) if self.requires else set()

    def as_read(self, visible: str, emulators: set[str], line: str | None = None) -> str:
        """A file as an emulator reading it instead is told to fetch it:
        by its card's name, with the name it reads when that differs.
        The line read "ares reads neo-epo.sp1" above a card titled
        neo-epo.bin."""
        lines = [line] if line is not None else sorted(self.line_readers)
        for key in lines:
            card = self.card_names.get((key, visible))
            if card is None:
                continue
            reads = {self.read_as[(key, visible, e)] for e in emulators
                     if (key, visible, e) in self.read_as}
            written = self.written.get(visible, code_span(card))
            # A linked name (a file under Arcade) keeps its link.
            shown = written if visible_name(written) == card else code_span(card)
            if len(reads) == 1 and next(iter(reads)) != card:
                return f"{shown} (as {code_span(next(iter(reads)))})"
            return shown
        return self.written.get(visible, code_span(visible))


_Read = tuple[str, dict, "str | None"]


def _section_reads(
    files: list[dict], consumers: FileConsumers, here: tuple[str, str] | None,
) -> tuple[dict[str, list[_Read]], list[dict]]:
    """The reads of each file the section names, by sha1, and the files the
    start line may name: the section's primaries, then the Arcade files
    its systems require."""
    from sitegen.render import system_section

    held = {str(f.get("sha1", "")) for f in files}
    primaries = [f for f in files if "/.variants/" not in f["path"]]
    kept: dict[str, list[_Read]] = {}
    for f in primaries:
        sha1 = str(f.get("sha1", ""))
        for emulator, entry in reading_pairs(sha1, consumers):
            if comes_with_app(entry):
                continue
            system = None
            systems = entry_systems(emulator, entry)
            if here is not None and systems:
                system = next((s for s in systems if system_section(s) == here), None)
                if system is None:
                    continue
            kept.setdefault(sha1, []).append((emulator, entry, system))
    candidates = list(primaries)
    known = (getattr(consumers, "_db", None) or {}).get("files", {})
    if here is not None:
        for sha1, emulator, entry, system in entries_by_section(consumers).get(here, []):
            record = known.get(sha1)
            parts = str((record or {}).get("path", "")).split("/")
            if (sha1 in held or not record or comes_with_app(entry) or ".variants" in parts
                    or len(parts) < 3 or parts[1] != "Arcade"):
                continue
            if sha1 not in kept:
                candidates.append({**record, "elsewhere": True})
            kept.setdefault(sha1, []).append((emulator, entry, system))
    return kept, candidates


class _SectionReads:
    """Each read of the files a start line may name, with the name the line
    writes for it."""

    def __init__(self, kept: dict[str, list[_Read]], ranked: list[dict],
                 consumers: FileConsumers) -> None:
        self.kept = kept
        self.rendered: dict[str, str] = {}
        for f in ranked:
            sha1 = str(f.get("sha1", ""))
            pairs = kept.get(sha1, [])
            name = code_span(setup_name(f, consumers, [(e, entry) for e, entry, _s in pairs]))
            if f.get("elsewhere"):
                name = f"[{name}]({markup.site_href(f'files/?sha1={sha1}')})"
            self.rendered[sha1] = name
        # A member read inside its archive is the archive's to name: FinalBurn
        # Neo reads sfix.sfix inside neogeo.zip, and the line had it read
        # sfix.sfix instead of neogeo.zip.
        self.archives = {visible_name(name): (name, sha1)
                         for sha1, name in reversed(self.rendered.items())}
        db = getattr(consumers, "_db", None) or {}
        self.known = db.get("files", {})
        self.by_name = db.get("indexes", {}).get("by_name", {})

    def archive_named(self, archive: str) -> tuple[str, str]:
        """The archive as the line names it, linked to its card when the
        collection holds one, with that card's sha1."""
        if archive in self.archives:
            return self.archives[archive]
        found = self.by_name.get(archive) or []
        found = [found] if isinstance(found, str) else sorted(found)
        found.sort(key=lambda s: "/.variants/" in str(self.known.get(s, {}).get("path", "")))
        if not found:
            return code_span(archive), ""
        return f"[{code_span(archive)}]({markup.site_href(f'files/?sha1={found[0]}')})", ""

    def reading(self, f: dict) -> Iterator[tuple[str, dict, str | None, str, str]]:
        """Each read of a file: the emulator, its entry, the system, the
        name the line writes and the sha1 of the card it names."""
        sha1 = str(f.get("sha1", ""))
        for emulator, entry, system in self.kept.get(sha1, []):
            name, named = self.rendered[sha1], sha1
            if entry.get("archive"):
                name, named = self.archive_named(str(entry["archive"]))
            yield emulator, entry, system, name, named


def _weak_starts(ranked: list[dict], reads: _SectionReads) -> tuple[dict[str, set[str]], set[str]]:
    """The emulators requiring each file, and the files that are extras.

    A file as many of whose readers require another file and read this
    one only when present is an extra, not a start file: NAOMI opened on
    hod2bios.zip, which 13 of the 19 emulators listing it read beside
    naomi.zip for the House of the Dead 2 alone."""
    requiring: dict[str, set[str]] = {}
    optional: dict[str, set[str]] = {}
    for f in ranked:
        for emulator, entry, _system, name, named in reads.reading(f):
            if entry.get("hle_fallback"):
                continue
            side = requiring if entry.get("required", True) else optional
            side.setdefault(named or visible_name(name), set()).add(emulator)
    needs_other = {emulator: {key for key, emulators in requiring.items() if emulator in emulators}
                   for emulators in requiring.values() for emulator in emulators}
    weak = {key for key, emulators in requiring.items()
            if len(emulators) <= len({e for e in optional.get(key, ())
                                      if needs_other.get(e, set()) - {key}})}
    return requiring, weak


def _group_place(emulator: str, entry: dict) -> tuple[str, str, tuple[str, ...]] | None:
    """The requirement a member of a group answers, or None outside a group."""
    if entry.get("group") and entry.get("required", True) and not entry.get("hle_fallback"):
        return (emulator, str(entry["group"]),
                tuple(sorted(str(r) for r in entry.get("region") or [])))
    return None


def _chosen_members(ranked: list[dict], reads: _SectionReads,
                    requiring: dict[str, set[str]]) -> dict[tuple, str]:
    """A group's members are one requirement, any of them answering it: the
    emulator requires on the line the member most emulators require, its
    search order breaking a tie. PicoDrive's four Europe Mega CD names
    each read as a file to get beside the bios_CD_E.bin of every other."""
    members: dict[tuple, list[tuple[tuple, str]]] = {}
    for f in ranked:
        for emulator, entry, _system, name, named in reads.reading(f):
            place = _group_place(emulator, entry)
            if place is not None:
                member = named or visible_name(name)
                rank = (-len(requiring.get(member, ())),
                        entry["priority"] if isinstance(entry.get("priority"), int) else NO_PRIORITY,
                        visible_name(name))
                members.setdefault(place, []).append((rank, member))
    return {place: min(found)[1] for place, found in members.items()}


def _add_start_read(group: _StartGroup, f: dict, read_by: tuple[str, dict, str, str],
                    weak: set[str]) -> None:
    """One read of a file into its system's group: ``read_by`` is the
    emulator, its entry, the name the line writes and the card's sha1."""
    emulator, entry, name, named = read_by
    if named:
        group.sha1s.setdefault(visible_name(name), named)
    if emulator not in group.emulators:
        group.emulators.append(emulator)
    if entry.get("hle_fallback"):
        add_name(group.optional, name)
        group.hle.add(emulator)
        return
    if not entry.get("required", True):
        add_name(group.extra, name)
        return
    group.require(name, emulator)
    read = str(entry.get("archive") or entry.get("name") or visible_name(name))
    card = str(entry["archive"]) if entry.get("archive") else str(f["name"])
    regions = sorted({str(r) for r in entry.get("region") or []})
    for region in regions or [""]:
        add_name(group.by_region.setdefault(region, []) if region else group.plain, name)
        group.read_for(region, name, emulator, read, card)
        if (named or visible_name(name)) in weak:
            group.extras.add((region, visible_name(name)))


def _start_groups(
    files: list[dict], consumers: FileConsumers, section: tuple[str, str] | None
) -> dict[str | None, _StartGroup]:
    """The files of a section an emulator reads, by the system they are
    read for. An entry is the section's when one of its systems leads
    here: the DS section named five DSi files, and the NES one FBNeo's
    YM2608 sample, read for a system with no section of its own. An entry
    that names no system, in a profile of several, reads the section's own
    console. A file the system requires but filed under
    Arcade, where sets serve every machine, is named too, linked to its
    card: the Neo Geo BIOS. One filed under another console is that
    console's, whatever system an emulator files it under (BizHawk reads
    the Mega CD BIOS for its Genesis), and one under Other is a single
    emulator's, its shaders and fonts. A file the emulator ships with is
    no file to fetch."""
    from model.systemnames import heading_name, system_name
    from model.collection import manufacturer_slug

    here = (manufacturer_slug(section[0]), section[1]) if section else None
    kept, candidates = _section_reads(files, consumers, here)

    groups: dict[str | None, _StartGroup] = {}
    ranked = sorted(candidates, key=lambda f: card_rank(f, consumers))
    reads = _SectionReads(kept, ranked, consumers)
    requiring, weak = _weak_starts(ranked, reads)
    chosen = _chosen_members(ranked, reads, requiring)

    for f in ranked:
        for emulator, entry, system, name, named in reads.reading(f):
            place = _group_place(emulator, entry)
            if place is not None and chosen.get(place) != (named or visible_name(name)):
                continue
            try:
                key = system_name(system) if system else None
            except KeyError:
                key = None
            group = groups.setdefault(key, _StartGroup())
            _add_start_read(group, f, (emulator, entry, name, named), weak)
    named_keys = [key for key in groups if key is not None]
    if None in groups and named_keys:
        # An entry that names no system reads the section's own console.
        heading = heading_name(*section) if section else None
        groups[heading if heading in groups else named_keys[0]].absorb(groups.pop(None))
    return groups


def start_with(
    files: list[dict], consumers: FileConsumers, first_below: bool = True,
    section: tuple[str, str] | None = None,
) -> list[str]:
    """The line a console section opens on: the files an emulator requires,
    by the region the emulator picks each for, and by system when the
    section holds several.

    ``section`` is the (manufacturer, console) the files are under: an
    entry read for another console's system is left to that console.
    Read from the profiles' system, required, hle_fallback and region
    fields, never typed per system. A system most of whose emulators run
    without its files says so, and names the few that require one. A
    section where no emulator reads a file gets no line.
    """
    return _start(files, consumers, first_below, section)[0]


def start_order(
    files: list[dict], consumers: FileConsumers, section: tuple[str, str] | None = None,
) -> list[str]:
    """The sha1s of the files a section's start line names, in its order:
    the cards come in that order, so "first below" is true."""
    return _start(files, consumers, True, section)[1]


def _start(
    files: list[dict], consumers: FileConsumers, first_below: bool,
    section: tuple[str, str] | None,
) -> tuple[list[str], list[str]]:
    """The start line and the sha1s it names, in order."""
    groups = _start_groups(files, consumers, section)
    sha1s: dict[str, str] = {}
    for group in groups.values():
        for visible, card_sha1 in group.sha1s.items():
            sha1s.setdefault(visible, card_sha1)
    held = {str(f.get("sha1", "")) for f in files}
    lines = _lead_file(groups)
    if not lines:
        lines = _group_lines(groups, first_below, held, sha1s,
                             section_label(*section) if section and section != OTHER_ARCADE else "")
    order: list[str] = []
    for line in lines:
        for visible in re.findall(r"`([^`]*)`", line):
            sha1 = sha1s.get(visible)
            if sha1 and sha1 not in order:
                order.append(sha1)
    return [_link_held_names(line, sha1s, held) for line in lines], order


def _link_held_names(line: str, sha1s: dict[str, str], held: set[str]) -> str:
    """Each file the start line names leads to its card, where it downloads:
    the Apple II line named eight files and none was a way to get one."""
    def link(match: re.Match) -> str:
        sha1 = sha1s.get(match[1], "")
        return f"[{match[0]}](#{card_anchor(sha1)})" if sha1 in held else match[0]
    # A name inside a link already (a "Keep it zipped" archive) stays as
    # is, and so does the name a file is read under, "(as `d2fdc.zip`)".
    return re.sub(r"(?<!\[)(?<!\(as )`([^`]*)`(?!\]\()", link, line)


def _group_lines(
    groups: dict[str | None, _StartGroup], first_below: bool, held: set[str],
    sha1s: dict[str, str], console: str = "",
) -> list[str]:
    """One block per system, as the section opens on them. ``console`` names
    the section in a line that picks a BIOS by region."""
    keys = sorted(groups, key=lambda k: str(k).casefold())
    blocks: dict[str | None, list[tuple[str, str]]] = {}
    for key in keys:
        block = _group_start(groups[key], first_below and not blocks)
        if block and first_below and not blocks:
            # "First below" holds only when the first file named is a card
            # of this page: the Neo Geo BIOS is filed under Arcade.
            first = re.search(r"`([^`]*)`", block[0][1])
            if first and sha1s.get(first[1]) not in held:
                block = _group_start(groups[key], False)
        if block:
            blocks[key] = block
    if not blocks:
        return []
    if len(blocks) == 1:
        return _start_lines(next(iter(blocks.values())), console)
    if all(lead == "*" for block in blocks.values() for lead, _text in block):
        # No machine of the section needs a file: the SNES said "Start with"
        # over two lines that each said no file is needed.
        lines = ["**No file needed** on any of these machines:", ""]
        lines += [f"- **{key}**: {text.lstrip(': ')}"
                  for key, block in blocks.items() for _lead, text in block]
        return [*lines, ""]
    lines = ["**Start with** the files of the machine:", ""]
    for key, block in blocks.items():
        for lead, text in block:
            if lead == "*":
                lines.append(f"- **{key}**: no file needed{text}")
                continue
            if lead == "+":
                # What the others read instead ends the machine's line.
                end = "" if lines[-1].endswith(".") else "."
                lines[-1] = f"{lines[-1]}{end} {text}"
                continue
            lines.append(f"- **{key}, {lead}**: {text}" if lead else f"- **{key}**: {text}")
    return [*lines, ""]


def _display_names(emulators: set[str] | list[str]) -> list[str]:
    return sorted({emulator_display(e) for e in emulators}, key=str.casefold)


def _names_counted(names: list[str], most: int = 3, noun: str = "") -> str:
    """Names as "a, b and c", the ones past ``most`` counted: "a, b, c and
    12 more". One past ``most`` is named, not counted as "1 more"."""
    if len(names) > most + 1:
        more = f"{len(names) - most} more" + (f" {noun}" if noun else "")
        return f"{', '.join(names[:most])} and {more}"
    return series(names)


def _lead_file(groups: dict[str | None, _StartGroup]) -> list[str]:
    """A section of several systems where most emulators require one file:
    that file first, and the emulators that read another instead. The Neo
    Geo section listed three machines, and neogeo.zip, which 26 emulators
    read, came after a file ares alone reads."""
    if len(groups) < 2:
        return []
    emulators: set[str] = set()
    requires: dict[str, set[str]] = {}
    written: dict[str, str] = {}
    holder: dict[str, _StartGroup] = {}
    for group in groups.values():
        emulators.update(group.emulators)
        for visible, readers in group.requires.items():
            requires.setdefault(visible, set()).update(readers)
            written.setdefault(visible, group.written[visible])
            holder.setdefault(visible, group)
    if not requires:
        return []
    top = max(requires, key=lambda v: len(requires[v]))
    readers = requires[top]
    if 2 * len(readers) <= len(emulators):
        return []
    zipped = " Keep it zipped." if top.casefold().endswith(".zip") else ""
    names = _display_names(readers)
    said = (_names_counted(names, 2, "emulators") if len(names) > 2
            else series(names))
    lines = [f"**Start with** {written[top]}.{zipped} {said} read{'s' if len(names) == 1 else ''} it.",
             ""]
    # The emulators that require other files and not this one, by the
    # files they require, each by its card's name.
    others: dict[tuple[str, ...], set[str]] = {}
    for emulator in emulators - readers:
        theirs = tuple(holder[v].as_read(v, {emulator}) for v in requires
                       if emulator in requires[v])
        if theirs:
            others.setdefault(theirs, set()).add(emulator)
    sentences = []
    for files, who in sorted(others.items(), key=lambda item: (-len(item[1]), item[0])):
        names = _display_names(who)
        verb = "reads" if len(names) == 1 else "read"
        sentences.append(f"{_names_counted(names)} {verb} {series(list(files))} instead.")
    if sentences:
        lines += [" ".join(sentences), ""]
    return lines


@dataclass(frozen=True)
class _GroupWords:
    """How one system's start line says its files."""

    group: _StartGroup
    first_below: bool

    def listed(self, names: list[str], below: bool | None = None) -> str:
        below = self.first_below if below is None else below
        if len(names) <= START_WITH_NAMES:
            return ", ".join(names)
        # The first three by rank, the rest counted: "the 9 files" named
        # none, and the Neo Geo BIOS everyone reads is filed under Arcade.
        return f"{', '.join(names[:3])} and {count_text(len(names) - 3, 'more file')}" + (
            ", first below" if below else "")

    def instead_of(self, line: str, names: list[str], answered: set[str]) -> str:
        """What the emulators no other name answers read instead, one
        sentence per set of files: "FinalBurn Neo reads fdsbios.zip instead"."""
        group = self.group
        readers = group.line_readers.get(line, {})
        others: dict[tuple[str, ...], set[str]] = {}
        for emulator in sorted(set().union(*(readers.get(visible_name(n), set()) for n in names))
                               - answered):
            theirs = tuple(group.as_read(visible_name(n), {emulator}, line) for n in names
                           if emulator in readers.get(visible_name(n), set()))
            others.setdefault(theirs, set()).add(emulator)
        sentences = []
        for files, who in sorted(others.items(), key=lambda item: (-len(item[1]), item[0])):
            shown = _display_names(who)
            verb = "reads" if len(shown) == 1 else "read"
            sentences.append(f"{_names_counted(shown)} {verb} {series(list(files))} instead.")
        return " ".join(sentences)

    def split(self, line: str, names: list[str]) -> tuple[list[str], str, set[str]]:
        """A line's names as the files to start with, the sentence naming
        what other emulators read instead, and every emulator the line
        answers. Names no emulator requires beside another are other names
        for one slot: "fdsbios.zip, disksys.rom" read as two files to get."""
        group = self.group
        readers = group.line_readers.get(line, {})
        sets = {n: readers.get(visible_name(n), set()) for n in names}
        lead = max(names, key=lambda n: len(sets[n]))
        main = [n for n in names if n == lead or sets[n] <= sets[lead]]
        rest = [n for n in names if n not in main]
        # A file the lead's readers require beside it is a start file too,
        # unless most of its readers take it as an extra.
        main = [n for n in main if n == lead or (line, visible_name(n)) not in group.extras]
        return main, self.instead_of(line, rest, set(sets[lead])), set().union(*sets.values())


def _runs_without(words: _GroupWords) -> list[tuple[str, str]]:
    """The line of a system most of whose emulators run without its files,
    or nothing."""
    group = words.group
    requirers = group.requirers()
    hle = group.hle - requirers
    running = set(group.emulators) - requirers
    # One that replaces the file with its own code runs, with less
    # accuracy, and counts half: most PlayStation cores have such a
    # fallback, and a reader still starts with the BIOS.
    if not (requirers and 2 * len(requirers) <= 2 * len(running - hle) + len(hle)):
        return []
    free = _display_names(running)
    needing = _display_names(requirers)
    names = list(group.written.values())
    verb = "requires" if len(needing) == 1 else "require"
    if all(len(readers) == len(requirers) for readers in group.requires.values()):
        return [("*", f" with {_names_counted(free)}. Only {_names_counted(needing)} {verb} "
                      f"{words.listed(names, False)}.")]
    # Each requires some of the files: "bsnes, FinalBurn Neo and 3
    # more require 22 files" read as 22 files for a bsnes user.
    these = f"these {len(names)} files" if len(names) > START_WITH_NAMES else "these files"
    return [("*", f" with {_names_counted(free)}. Only {_names_counted(needing)} {verb} "
                  f"some of {these}: {words.listed(names, False)}.")]


def _region_lines(words: _GroupWords) -> tuple[list[tuple[str, str]], set[str], set[str]]:
    """The lines of the files picked by region, the emulators they answer
    and the names they give."""
    from model.region import PARENT

    group = words.group
    order = region_order()
    # A territory its region answers the same way adds nothing: Brazil
    # under Latin America.
    by_region = {r: names for r, names in group.by_region.items()
                 if group.by_region.get(PARENT.get(r, "")) != names}
    # Regions that need the same files share a line.
    regional: dict[tuple[str, ...], str] = {}
    answered: set[str] = set()
    shown: set[str] = set()
    for region in sorted(by_region, key=lambda r: (order.get(r, len(order)), r)):
        main, sentence, readers = words.split(region, by_region[region])
        answered |= readers
        shown |= {visible_name(n) for n in by_region[region]}
        text = f"{words.listed(main)}. {sentence}" if sentence else words.listed(main)
        same = next((rs for rs, held in regional.items() if held == text), None)
        if same is None:
            regional[(region,)] = text
        else:
            regional[same + (region,)] = regional.pop(same)

    out = [(", ".join(region_words(r) for r in regions), regional[regions])
           for regions in sorted(regional, key=lambda rs: (order.get(rs[0], len(order)), rs))]
    return out, answered, shown


def _plain_lines(words: _GroupWords, regional: bool, answered: set[str],
                 shown: set[str]) -> list[tuple[str, str]]:
    """The lines of the files every region needs, after the ``regional`` ones."""
    group = words.group
    out: list[tuple[str, str]] = []
    # A name a region line gives already is no "also", and one only
    # emulators no region line answers reads is an "instead": armsx1 reads
    # scph1001.bin where the others pick a BIOS by region.
    plain = [n for n in group.plain if visible_name(n) not in shown]
    if plain and regional:
        readers = group.line_readers.get("", {})
        also = [n for n in plain if readers.get(visible_name(n), set()) & answered]
        if also:
            out.append(("", words.listed(also)))
        sentence = words.instead_of("", [n for n in plain if n not in also], answered)
        if sentence:
            out.append(("+", sentence))
    elif plain:
        main, sentence, _readers = words.split("", plain)
        out.append(("", words.listed(main)))
        if sentence:
            out.append(("+", sentence))
    return out


def _group_start(group: _StartGroup, first_below: bool) -> list[tuple[str, str]]:
    """One system's start as (lead, text) pairs. The lead is the regions a
    line is for, "" the files every region needs, "*" the line of a system
    that runs without any file.

    A file is a start file when the emulators requiring it outweigh those
    that run without it. The Game Boy opened on dmg_boot.bin, which Emux
    GB alone of 13 requires, under a home page that says the Game Boy
    needs no BIOS."""
    words = _GroupWords(group, first_below)
    without = _runs_without(words)
    if without:
        return without
    out, answered, shown = _region_lines(words)
    out.extend(_plain_lines(words, bool(out), answered, shown))
    if not out and group.optional:
        out.append(("*", f"{without_files(group.emulators)}. "
                         f"For full accuracy: {words.listed(group.optional)}."))
    elif not out and group.extra:
        # The Mega Drive's emulators read the TMSS BIOS when it is there:
        # the section said nothing under a home page saying none is needed.
        out.append(("*", f"{without_files(group.emulators)}. "
                         f"Optional: {words.listed(group.extra, False)}."))
    return out


def _start_lines(block: list[tuple[str, str]], console: str = "") -> list[str]:
    """One system's start, as the lines its section opens on. A BIOS picked
    by region is named with its console: "playstation bios" found the
    PlayStation 2 page first, its file names holding "BIOS" and the
    PlayStation page's text never saying "PlayStation BIOS"."""
    lead, text = block[0]
    if lead == "*":
        return [f"**No file needed**{text}", ""]
    # What the emulators no line answers read instead, after the lines.
    instead = " ".join(text for lead, text in block if lead == "+")
    block = [(lead, text) for lead, text in block if lead != "+"]
    if len(block) == 1 and block[0][0] == "":
        named, _sep, _where = block[0][1].partition(", first below")
        below = " They come first below." if _sep else ""
        return [" ".join(filter(None, [f"**Start with**: {named}.{below}", instead])), ""]
    bios = f"the {console} BIOS" if console else "the BIOS"
    lines = [f"**Start with** {bios} for the region of the games:", ""]
    for lead, text in block:
        lines.append(f"- **{lead or 'Some emulators also require'}**: {text}")
    if instead:
        lines += ["", instead]
    return [*lines, ""]


def cards_markdown(cards: list[Card]) -> list[str]:
    """Primaries, then the variants in a closed block."""
    lines = [line for variant, card, _sha1 in cards if not variant for line in card]
    variants = [card for variant, card, _sha1 in cards if variant]
    if variants:
        # A variant gets the same card as a primary: the revision a
        # platform pins is the one a reader comes to find, and showed as
        # a name and a truncated MD5, nothing said who pins it.
        lines.extend(markup.details(
            "note", f"Variants ({len(variants)})", [line for card in variants for line in card]))
    return lines


def console_heading(manufacturer: str, console: str, label: str = "") -> str:
    """A console's heading, its name alone. An icon on 79 of 544 headings
    read as missing art on the rest, set the text at two positions on one
    page and faded out on one theme or the other. ``label`` is the text
    when it differs from the folder, the id staying the folder's."""
    return f"## {label or console} {{ #{console_anchor(manufacturer, console)} }}"


def romset_note(consoles: dict[str, list]) -> list[str]:
    """The line a page of MAME or FBNeo sets carries: an arcade player
    looking for the version found the answer only under Reference."""
    releases = romset_releases()
    if not any(str(f.get("name", "")) in releases for files in consoles.values() for f in files):
        return []
    return ["MAME and FBNeo sets must match the emulator's version. "
            f"[Which version each core reads]({ROMSET_FAQ}).", ""]


# The Arcade folder of files no board claims: the folder is named after
# its maker, which said nothing about what it holds.
OTHER_ARCADE = ("Arcade", "Arcade")
OTHER_ARCADE_LABEL = "Other arcade files"


def section_label(manufacturer: str, console: str) -> str:
    """The heading a section shows."""
    if (manufacturer, console) == OTHER_ARCADE:
        return OTHER_ARCADE_LABEL
    return SECTION_LABELS.get((manufacturer, console), console)
