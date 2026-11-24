"""Line mode's menu: the plan above it and the systems, cores and regions it narrows to."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from installer.choices import (
    GAMES_REQUIRED_WORDS,
    GamesChoice,
    available_choices,
    choosable_cores,
    core_files,
    parse_selection,
    recorded_axes,
)
from installer.console import _ask, _quit
from installer.datadirs import data_directory_state, data_fetch_bytes, select_data_directories
from installer.destination import _last_name, on_its_card, shown_bios_folder
from installer.local_copies import plan_local_copies
from installer.frontend_folders import save_lines
from installer.host_fs import _is_file
from installer.install_record import _RECORD_TAKEN
from installer.invocation import _INVOCATION
from installer.line_folder import _ask_from_folder
from installer.local_check import not_in_place, read_in_place
from installer.manifest import OTHER_SYSTEMS
from installer.narrowing import _chosen, narrow
from installer.offline import LOCAL, _offline_only, offline_named
from installer.paths import _destination_path, _entry_path, shown_path
from installer.plan_words import (
    INSTALLED_ONLY,
    SHARED_NOTE,
    _SHARED_SHORT,
    _core_sized,
    _size_lines,
    _sized,
    _system_sized,
    choosable_systems,
    chosen_systems,
    core_count_words,
    emptied_words,
    folder_warnings,
    listed_systems,
    narrowing_words,
    systems_in_order,
    unavailable_lines,
)
from installer.platforms import OTHER_TITLE, display_name, system_title
from installer.regions import region_title
from installer.tally import _bytes, game_data_state, kinds_definition, leave_out_game_data, parts_words, tally
from installer.terminal import terminal_size
from installer.text import _no_widow, _pad, _plural, _wrap, agree, cell_width, format_size, screen_text

if TYPE_CHECKING:
    from installer.game_folders import GamesPlan
    from installer.tally import Tally


def _pick(
    title: str, rows: list[tuple[str, list[dict]]], ordered: bool = False,
    sizer: Callable[[list[dict]], str] = _sized, labels: dict | None = None,
    note: str = "", short: dict | None = None,
) -> list[str]:
    """Numbered list of names. An empty answer keeps every one.

    sizer says what each name holds, labels how each one is shown, short
    in fewer words where those take fewer lines (a system's title without
    its id at 40 columns), note what the list needs said, under it.
    """
    if not rows:
        return []
    print(f"\n{title}")
    shown = {name: screen_text((labels or {}).get(name, name)) for name, _files in rows}
    sizes = {name: sizer(files) for name, files in rows}
    # One cell short of the terminal: a line as wide as it was folded by
    # some terminals, the next row then starting on its last cell.
    cols = terminal_size()[0] - 1
    # The fewest lines, the whole words where they cost no line: one
    # wording for the whole list, the id dropped where it takes a tenth
    # more lines (40 columns).
    briefs = [shown] + ([{name: screen_text(short.get(name, name)) for name, _files in rows}]
                        if short else [])
    layouts = [(len(lines) * (10 if brief is shown else 11), words, lines)
               for brief in briefs for words in range(3)
               for lines in [_pick_lines(rows, brief, sizes, cols, words)]]
    _cost, words, lines = min(layouts, key=lambda layout: layout[:2])
    for line in lines:
        print(line)
    notes = [*([SHARED_NOTE] if words and any(_SHARED_SHORT in size for size in sizes.values())
               else []), *([note] if note else [])]
    if notes:
        # At the terminal's width too: the note on the other systems passed
        # 40 columns.
        print("\n" + "\n".join(piece for text in notes
                                for piece in _no_widow(_wrap(text, cols, ""), cols)))
    hint = "order of preference, e.g. 2,1" if ordered else "e.g. 1,3-5"
    while True:
        text = _ask(f"Numbers ({hint}), Enter for all, q to quit: ")
        if not text:
            return []
        if text.lower() == "q":
            _quit()
        try:
            chosen = parse_selection(text, len(rows), ordered=ordered)
        except ValueError as exc:
            print(f"  {exc}")
            continue
        if chosen:
            return [rows[number - 1][0] for number in chosen]


def _pick_lines(rows: list[tuple[str, list[dict]]], shown: dict, sizes: dict,
                cols: int, words: int = 0) -> list[str]:
    """The numbered rows of a line question, cols wide at most. The sizes
    stand in one column placed for the labels, where every size of one
    part fits beside the longest label that leaves it room: the column was
    placed for the longest size, and every row but five took two lines.
    A row keeps one line where
    its label and its size fit, a longer size goes on under its column, and
    a label too long for the column takes its own line."""
    width = len(str(len(rows)))
    lead = 2 + width + 2
    plain = [cell_width(size) for size in sizes.values() if "shared" not in size]
    least = max([*plain, 16]) if plain else 16
    labels = sorted(cell_width(label) for label in shown.values())
    name_width = max([label for label in labels if lead + label + 2 + least <= cols]
                     or [0])
    column = lead + name_width + 2
    lines = []
    for index, (name, _files) in enumerate(rows, 1):
        label, size = shown[name], sizes[name]
        number = f"  {index:>{width}}) "
        if name_width and cell_width(label) <= name_width:
            parts = _size_lines(size, cols - column, words)
            lines.append(f"{number}{_pad(label, name_width)}  {parts[0]}")
            lines += [f"{' ' * column}{part}" for part in parts[1:]]
            continue
        # The size beside the label only where all of it fits there: its
        # first part alone left "21 files, 1.4 MB," with its shared files
        # unsaid.
        fitted = _size_lines(size, cols, words)
        whole = fitted[0] if len(fitted) == 1 else size
        if cell_width(f"{number}{label}  {whole}") <= cols:
            lines.append(f"{number}{label}  {whole}")
            continue
        lines += [f"{number}{part}" if not at else f"{' ' * lead}{part}"
                  for at, part in enumerate(_no_widow(_wrap(label, cols - lead, ""),
                                                      cols - lead))]
        at = column if name_width and cols - column >= least else lead
        lines += [f"{' ' * at}{part}" for part in _size_lines(size, cols - at, words)]
    return lines


def _menu_trees_kept(trees: list[dict], kept: list[dict], narrowed: bool,
                     current: object) -> list[dict]:
    """The data trees of the files a line menu choice keeps."""
    return select_data_directories({"data_directories": trees}, kept,
                                   narrowed or current is not None,
                                   isinstance(current, GamesChoice) and current.required,
                                   current.plan if isinstance(current, GamesChoice) else None,
                                   chosen_systems(current))


class _SelectionMenu(NamedTuple):
    """What each round of the line menu reads, as it was given."""

    plat: str
    files: list[dict]
    omitted: list[dict]
    installed: tuple[list[dict], list[dict]] | None
    manifest: dict | None
    bios_path: Path | None
    dry_run: bool
    given: tuple[list[str], list[str], list[str]] | GamesChoice | None
    played: GamesPlan | None
    cut: list[bool] | None

    def choice(self, current: object, cutting: bool) -> tuple[list[dict], list[dict]]:
        return menu_choice(self.files, self.omitted, self.installed, current, cutting)


def _print_menu_enter(whole: str, emptied: str, dry_run: bool, offline: bool) -> None:
    """The Enter line of the line menu, none for a choice that keeps no file."""
    if emptied:
        pass
    elif dry_run:
        print(f"  Enter) list {whole}, nothing is written")
    elif offline and LOCAL.folders:
        print("  Enter) install what is found in "
              + ", ".join(screen_text(shown_path(index.label)) for index in LOCAL.folders))
    elif offline:
        print("  Enter) check the BIOS folder, nothing can be downloaded")
    else:
        print(f"  Enter) install {whole}")


def _print_menu_keys(menu: _SelectionMenu, current: object, shown: list[dict],
                     cutting: bool, games: Tally, emptied: str, axes: str) -> list[str]:
    """The lettered lines of the line menu, and the keys it takes."""
    played, installed = menu.played, menu.installed
    playing = bool(played is not None and played.games)
    if playing and isinstance(current, GamesChoice):
        other = GamesChoice(current.plan, not current.required)
        print(f"  r) {GAMES_REQUIRED_WORDS if other.required else 'every file the games read'}"
              f": {_sized(menu.choice(other, cutting)[0])}")
        print(f"  e) everything, whatever the games: {_sized(shown)}")
    elif playing and played is not None:
        kept_games = menu.choice(GamesChoice(played), cutting)[0]
        print(f"  h) only for the games {played.where()}: {_sized(kept_games)}")
    # The screen's "Same choice as last time: no": the whole list.
    widen = (menu.plat in _RECORD_TAKEN and current is not None
             and not (playing and isinstance(current, GamesChoice)))
    if widen:
        print(f"  e) everything: {_sized(shown)}")
    if installed is not None and current != INSTALLED_ONLY:
        print(f"  i) only what the installed cores read: {_sized(installed[0])}")
    choosable = bool(axes)
    if choosable:
        print(f"  c) choose {axes}" + (" again" if current is not menu.given else ""))
    # The screen's "Copy the BIOS files from an old card or a folder".
    copying = not menu.dry_run
    if copying:
        print("  f) copy from a folder or an old card")
    if menu.cut is not None and games.games:
        # The screen's row: one label, its state first.
        print(f"  g) {game_data_state(menu.cut[0], games)}: "
              f"{'keep it' if menu.cut[0] else 'leave it out'}")
    print("  q) quit")
    return [*([] if emptied else [""]), "q", *(["c"] if choosable else []),
            *((["r", "e"] if isinstance(current, GamesChoice) else ["h"]) if playing else []),
            *(["e"] if widen else []),
            *(["i"] if installed is not None and current != INSTALLED_ONLY else []),
            *(["f"] if copying else []), *(["g"] if games.games else [])]


def _menu_answered(
    menu: _SelectionMenu, answer: str,
    current: tuple[list[str], list[str], list[str]] | str | GamesChoice | None,
) -> tuple[list[str], list[str], list[str]] | str | GamesChoice | None:
    """The choice a key of the line menu makes, f copying from a folder."""
    if answer == "r" and isinstance(current, GamesChoice):
        return GamesChoice(current.plan, not current.required)
    if answer == "e":
        return None
    if answer == "h" and menu.played is not None:
        return GamesChoice(menu.played)
    if answer == "i":
        return INSTALLED_ONLY
    if answer == "c":
        return _choose_narrowing(menu.files, menu.omitted, menu.manifest, menu.bios_path)
    _ask_from_folder(menu.files, menu.bios_path)
    return current


class MenuContext(NamedTuple):
    """The list the line menu narrows, and the folder and setup it is for."""

    plat: str
    files: list[dict]
    omitted: list[dict]
    installed: tuple[list[dict], list[dict]] | None = None
    name: str = ""
    data_trees: list[dict] | None = None
    bios_path: Path | None = None
    manifest: dict | None = None
    narrowed: bool = False


def _prompt_custom_selection(
    context: MenuContext, *, dry_run: bool = False, choosable: bool = True,
    given: tuple[list[str], list[str], list[str]] | GamesChoice | None = None,
    command: Callable[[object], str] | None = None, cut: list[bool] | None = None,
    note: str = "", played: GamesPlan | None = None,
) -> tuple[list[str], list[str], list[str]] | str | GamesChoice | None:
    """Offer to narrow the install by system, core and region.

    cut, given for a list that marks its game data, holds whether g left
    it out: one key, as one row of the screen's plan, toggles it, and the
    caller applies it as --no-game-data does.

    Enter installs everything, the default most runs want. Returns None
    then, INSTALLED_ONLY for what `installed` (the files the cores found
    installed read) holds, or the three choices. Each empty list keeps
    everything on its axis. A list that records no system (a pack's own)
    has no c: the menu and its folder line are still shown, a pack having
    installed at once into a folder named only after Done. given is what
    --system, --core and --region named: Enter keeps it, c chooses anew from
    every system. The menu was skipped, and the folder never named.

    A choice made here is counted again before anything is written, as the
    screen's Confirm counts it: the menu comes back narrowed, with the
    command that makes the same choice (command, given the choice), and
    Enter installs. c installed as soon as the cores were answered, "Enter
    for all" read as a choice. narrowed says the list was narrowed before
    the menu (--target, --no-game-data): the data trees kept are then those
    of the systems kept, as the plan and --dry-run count them. note is said
    under the head (game_data_only_words). played, the games of the card
    when it holds some, is the first choice (h), the whole list one key
    away (e), and r keeps only what the games cannot start without.
    """
    plat, files, omitted, installed = (context.plat, context.files, context.omitted,
                                       context.installed)
    name, bios_path, manifest, narrowed = (context.name, context.bios_path, context.manifest,
                                           context.narrowed)
    trees = context.data_trees or []
    menu = _SelectionMenu(plat, files, omitted, installed, manifest, bios_path, dry_run,
                          given, played, cut)
    current: tuple[list[str], list[str], list[str]] | str | GamesChoice | None = given
    if current is None and played is not None and played.games:
        current = GamesChoice(played)
    toggled = False
    if bios_path is not None and not dry_run and current != INSTALLED_ONLY:
        kept = menu.choice(current, False)[0]
        kept_trees = _menu_trees_kept(trees, kept, narrowed, current)
        if kept and all_in_place(kept, kept_trees, bios_path):
            # Read before the menu, as the screen reads before it asks: a
            # rerun was offered an install that installs nothing, then told
            # so twice. The check after it reads none
            # of it again (_HEAD_READS).
            print(f"\n{name or display_name(plat)}: "
                  f"{_plural(len(kept) + sum(len(t.get('files') or {}) for t in kept_trees), 'file')}"
                  ", every one in place: nothing to install.")
            print(f"  BIOS folder: {shown_path(shown_bios_folder(bios_path, kept))}")
            return current
    while True:
        cutting = bool(cut and cut[0])
        shown, shown_omitted = ((leave_out_game_data(files, omitted)[:2])
                                if cutting else (files, omitted))
        # The game data of the choice the head counts, which g takes out of
        # it or puts back: counted over the whole list, it said 5089 files
        # under a head counting 12 for one system. Not offered for a
        # choice that holds none.
        games = tally(menu.choice(current, False)[0] if cut is not None else [])
        kept = menu.choice(current, cutting)[0]
        # A choice that keeps no file says so in the headline, as the screen
        # does, and offers no Enter and no command: both installed nothing.
        emptied = (emptied_words([system_title(name_, manifest) for name_ in current[0]],
                                 cutting)
                   if isinstance(current, tuple) and not kept else "")
        _print_menu_head(context._replace(files=shown, omitted=shown_omitted, data_trees=trees),
                         current, object() if toggled else given,
                         chosen=menu.choice(current, cutting),
                         cut_games=games.games if cutting else 0, emptied=emptied,
                         note=note if current is given else "")
        if (current is not given or toggled) and command is not None and not emptied:
            print(f"  Same choice without questions: {screen_text(command(current))}")
        offline = _offline_only()
        if offline:
            # Said before the menu: "install everything" was offered, then
            # nothing came and the run said Done.
            print(f"  {offline_named()}: only the files found on this machine are installed"
                  + ("." if LOCAL.folders else ", and no --from names a folder to copy "
                     "them from."))
        # A dry run installs nothing: "install everything" was asked before it.
        # Offline with nothing to copy from, nothing can be installed but
        # what is in place already.
        whole = ("everything" if current is None
                 else f"what the games {played.where()} need"
                 if isinstance(current, GamesChoice) and played is not None else "these")
        _print_menu_enter(whole, emptied, dry_run, offline)
        # What c asks, named: "systems, cores and regions" was offered with
        # a pack that records systems only.
        axes = narrowing_words(files, omitted) if choosable else ""
        choosable = bool(axes)
        keys = _print_menu_keys(menu, current, shown, cutting, games, emptied, axes)
        others = [key for key in keys if key not in ("", "q")]
        answer = _ask("> ").lower()
        while answer not in keys:
            print(f"  Type {', '.join([*([] if emptied else ['Enter']), *others])} or q.")
            answer = _ask("> ").lower()
        if answer == "":
            return current
        if answer == "q":
            _quit()
        if answer == "g" and cut is not None and games.games:
            cut[0] = not cut[0]
            toggled = True
        else:
            current = _menu_answered(menu, answer, current)


def _print_menu_head(
    context: MenuContext, current: object, given: object, *,
    chosen: tuple[list[dict], list[dict]] | None = None,
    cut_games: int = 0, emptied: str = "", note: str = "",
) -> None:
    """The plan above the line menu: what the choice holds, its folder, what
    stands in its way and where the save files go, as the screen's plan.
    chosen is what the choice keeps (menu_choice), the list every count of
    the head is taken from. cut_games is the game data g left out of it."""
    plat, files, omitted, installed = (context.plat, context.files, context.omitted,
                                       context.installed)
    name, bios_path, manifest = context.name, context.bios_path, context.manifest
    trees, narrowed = context.data_trees or [], context.narrowed
    shown, kept_omitted = chosen or menu_choice(files, omitted, installed, current, False)
    # The trees of the systems kept: 2636 data files of blueMSX, Dolphin
    # and PPSSPP were counted for every --system tried.
    kept_trees = _menu_trees_kept(trees, shown, narrowed, current)
    data = sum(len(entry.get("files") or {}) for entry in kept_trees)
    data_size = sum(meta.get("size", 0) for entry in kept_trees
                    for meta in (entry.get("files") or {}).values())
    named = ""
    if current == INSTALLED_ONLY:
        named = ", only what the installed cores read"
    elif isinstance(current, GamesChoice):
        named = f", {current.words()}" + (" (--for-games)" if current is given
                                          and plat not in _RECORD_TAKEN else "")
    elif isinstance(current, tuple):
        systems, cores, regions = current
        # A recorded choice was typed by nobody: no option is named.
        flag = current is given and plat not in _RECORD_TAKEN
        listed = choosable_systems(files, omitted, cores, regions)
        total = len(listed)
        # The systems chosen that still hold a file: Sega Dreamcast holding
        # only game data, g left the line at "2 of 8" where the screen,
        # which drops it, said "1 of 8".
        held = len(set(systems) & set(listed))
        named = ", " + ", ".join(filter(None, [
            f"for {held} of {total} systems" + (" (--system)" if flag else "")
            if systems else "",
            # Out of the cores the systems chosen offered, as Cores counts
            # them: "1 core chosen" read as one of one. A flag typed is
            # named after the words, never alone: "--region." stood as a
            # sentence of its own.
            core_count_words(cores, choosable_cores(files, omitted, systems))
            + (" (--core)" if flag else "") if cores else "",
            "regions ranked" + (" (--region)" if flag else "") if regions else ""]))
        named = "" if named == ", " else named
    if current is not given:
        print("\n  Counted again for these choices. Nothing is written before Enter.")
    counts = tally(shown)
    if emptied:
        # The screen's headline for a choice that keeps no file.
        print(f"\n{name or display_name(plat)}: {emptied}")
        if bios_path is not None:
            print(f"  BIOS folder: {shown_path(shown_bios_folder(bios_path, files))}")
        return
    # One total, data files in it, the kinds on the line under it adding up
    # to it, as the screen's headline. With --from,
    # what the folders hold first, as the screen's plan says it: nothing
    # said how many were found before Enter.
    found = (found_head(shown, kept_trees, bios_path)
             if LOCAL.folders and bios_path is not None else "")
    print(f"\n{name or display_name(plat)}: " + (found or (
          f"{_plural(counts.files + data, 'file')}, "
          f"{format_size(counts.size + data_size)}")) + named + ".")
    if note:
        print(f"  {note}")
    categorized = bool((manifest or {}).get("categorized"))
    kinds = counts if categorized else tally({"size": e.get("size")} for e in shown)
    parts = parts_words(kinds, data, data_size, cut_games)
    if parts:
        print(f"  {parts}.")
    defined = kinds_definition(categorized and bool(counts.games or cut_games), bool(data))
    if defined:
        print(f"  {defined}")
    if bios_path is None:
        return
    # Named before anything is written: line mode said where only after
    # Done, where the screen names it on every plan.
    print(f"  BIOS folder: {shown_path(shown_bios_folder(bios_path, files))}")
    for line in folder_warnings(plat, bios_path, shown, _INVOCATION, True,
                                on_its_card(plat, bios_path), kept_trees):
        print(f"  {line}")
    # The frontend's save directory, named as the end of the run and the
    # screen name it: "Onion's" before the menu, "RetroArch's" after.
    for line in save_lines(shown, kept_omitted, bios_path, display_name(plat, manifest)):
        print(f"  {line}")
    # The required files the collection cannot supply, named as the screen's
    # plan names them.
    for line in unavailable_lines([entry for entry in kept_omitted if entry.get("required")],
                                  manifest, bios_path, (manifest or {}).get("files") or shown):
        print(f"  {line}")


def found_head(files: list[dict], trees: list[dict], bios_path: Path) -> str:
    """What the --from folders hold of the files not in place, and what is
    left, in the screen plan's words: "6 found in OLD, 16 need the
    internet". "" when they hold none of them. A file of the wrong size is
    not in place. One of the right size is read, as check_local reads it:
    judged by its size, a wrong copy of the right size was in place, and
    "nothing to download" stood over a run that left it. What is read here is
    kept for the check after Enter (_HEAD_READS): a card read twice is read at
    the speed of its reader."""
    needed = not_in_place(bios_path, files)
    copies = plan_local_copies(needed, bios_path, None, LOCAL.folders)
    if not copies:
        return ""
    by_folder: dict[str, int] = {}
    for copy in copies.values():
        by_folder[copy.index.label] = by_folder.get(copy.index.label, 0) + 1
    data, data_bytes = 0, 0
    for tree in trees:
        _root, wanted, _present = data_directory_state(tree, bios_path, remember=True)
        data += len(wanted)
        data_bytes += data_fetch_bytes(tree, wanted)
    left = [entry for entry in needed if id(entry) not in copies]
    rest = len(left) + data
    where = ", ".join(f"{count} found in {_last_name(label)}"
                      for label, count in by_folder.items())
    if not rest:
        return f"{where}, nothing to download"
    if _offline_only():
        return f"{where}, {agree(rest, 'needs', 'need')} the internet"
    return f"{where}, {rest} to download ({format_size(_bytes(left) + data_bytes)})"


def all_in_place(files: list[dict], trees: list[dict], bios_path: Path) -> bool:
    """Whether every file and every data tree file is in place, read as the
    check reads it. Sizes first: a folder missing a file is told without a
    read. What is read is kept for the check (_HEAD_READS)."""
    paths = []
    for entry in files:
        try:
            path = _entry_path(bios_path, entry)
            if not _is_file(path) or path.stat().st_size != entry.get("size"):
                return False
        except (OSError, ValueError):
            return False
        paths.append((entry, path))
    for tree in trees:
        root = (_destination_path(bios_path, tree["dest"]) if tree.get("dest")
                else bios_path.resolve())
        for rel, meta in (tree.get("files") or {}).items():
            target = _destination_path(root, rel)
            try:
                if not _is_file(target) or target.stat().st_size != meta.get("size"):
                    return False
            except OSError:
                return False
    return (all(verdict == "up_to_date" for verdict in read_in_place(paths))
            and all(not data_directory_state(tree, bios_path, remember=True)[1]
                    for tree in trees))


def menu_choice(
    files: list[dict], omitted: list[dict],
    installed: tuple[list[dict], list[dict]] | None, current: object, cut: bool,
) -> tuple[list[dict], list[dict]]:
    """The files and omissions a choice at the line menu keeps, in the order
    the run applies it: the systems, cores and regions chosen, or what the
    installed cores read (i), then the game data left out (g)."""
    kept, kept_omitted = files, omitted
    if current == INSTALLED_ONLY and installed is not None:
        kept, kept_omitted = installed
    elif isinstance(current, GamesChoice):
        kept, kept_omitted = current.apply(files, omitted)
    elif isinstance(current, tuple):
        kept, kept_omitted = narrow(files, omitted, *current)
    return leave_out_game_data(kept, kept_omitted)[:2] if cut else (kept, kept_omitted)


def _choose_narrowing(files: list[dict], omitted: list[dict], manifest: dict | None,
                      bios_path: Path | None) -> tuple[list[str], list[str], list[str]]:
    """Systems, cores and regions asked one after the other, the systems
    titled and ordered as the screen's Choose systems lists them. A question
    with one answer is skipped: "Cores: 1) azahar" was asked after the 3DS
    alone was chosen."""
    listed = listed_systems(files) if "systems" in recorded_axes(files, omitted) else []
    systems_listed = (systems_in_order(listed, files, manifest, bios_path)
                      if len(listed) > 1 else [])
    # Said under the list it explains, before the question: above
    # "Systems:" it read as a heading.
    # One sentence wrapped at the width: its line break, placed for a
    # shorter title, left "platform" alone on a line.
    note = (f"'{OTHER_TITLE}' holds what cores load for systems this platform "
            "does not list, such as game engines and extra computers."
            if OTHER_SYSTEMS in systems_listed else "")
    labels = {}
    for system in systems_listed:
        title = system_title(system, manifest)
        labels[system] = title if system in title or system == OTHER_SYSTEMS \
            else f"{title}  {system}"
    systems = _pick("Systems:", [
        (system, [f for f in files if _chosen(f, {system})]) for system in systems_listed
    ], sizer=_system_sized, labels=labels, note=note,
        short={system: system_title(system, manifest) for system in systems_listed})
    kept, kept_omitted = narrow(files, omitted, systems, [], [])

    cores: list[str] = []
    core_names = choosable_cores(kept, kept_omitted)
    if len(core_names) > 1:
        print("\nThe platform's own files for these systems are always kept.")
        # Every core is kept, as Cores draws them all ticked: a list of
        # numbers read as nothing chosen yet.
        print("Every core's extra files are kept: Enter keeps them all, numbers keep "
              "only those cores.")
        cores = _pick("Cores:", [(core, core_files(kept, core)) for core in core_names],
                      sizer=_core_sized)
        kept, kept_omitted = narrow(kept, kept_omitted, [], cores, [])

    regions: list[str] = []
    region_names = available_choices(kept, kept_omitted)["regions"]
    if region_names:
        print("\nSome systems have one BIOS per region. Keeping only the")
        print("preferred region removes the others where a match exists.")
        regions = _pick("Regions:", [
            (region, [f for f in kept if region in (f.get("regions") or [])])
            for region in region_names
        ], ordered=True, labels={region: region_title(region) for region in region_names})
    return systems, cores, regions
