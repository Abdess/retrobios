"""The opening of an emulator page: what it needs, by region or under any name, and what the collection holds."""

from __future__ import annotations

from collections.abc import Callable

from core.text import series
from sitegen.emulatorcards import any_name_bios, named_example, named_system_link
from sitegen.filebadges import region_words
from sitegen.install import comes_with_app, data_folder_block, standalone_place
from sitegen.render import code_span, count_text
from sitegen.runsections import system_name


def _emulator_slots(files: list[dict]) -> list[list[dict]]:
    """The entries of each slot, as verify --emulator and the gaps page
    count them, leaving out the slots the app ships."""
    from packs.crossref import slot_key

    slots: dict[tuple, list[dict]] = {}
    for f in files:
        slots.setdefault(slot_key(f), []).append(f)
    return [group for group in slots.values() if not all(comes_with_app(f) for f in group)]


def _set_names(value: object) -> list[str]:
    """The sets an entry belongs to: group takes a name, a list or a map."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, dict)):
        return [str(name) for name in value]
    return []


def _requirements(files: list[dict], groups: dict | None) -> list[list[dict]]:
    """Each thing the emulator needs: the members of a required set, any one
    of which fills it (DuckStation's ps-bios, 105 images), or a required
    file of its own. load_emulator_profiles marks every member of a
    required set required, so counted per file DuckStation read "105
    required" for one BIOS."""
    required_sets = {name for name, spec in (groups or {}).items()
                     if isinstance(spec, dict) and spec.get("required")}
    sets: dict[str, list[dict]] = {}
    alone: list[list[dict]] = []
    for f in files:
        if f.get("required") is not True or comes_with_app(f):
            continue
        names = [name for name in _set_names(f.get("group")) if name in required_sets]
        if names:
            for name in names:
                sets.setdefault(name, []).append(f)
        else:
            alone.append([f])
    return [*sets.values(), *alone]


def _regional_set(requirements: list[list[dict]]) -> list[dict]:
    """The one requirement, a set whose members the code picks by the game's
    region, or [] when there is no such single choice."""
    if len(requirements) != 1 or len(requirements[0]) < 2:
        return []
    members = requirements[0]
    if not all(f.get("region") for f in members):
        return []
    return members if len({region_words(f["region"]) for f in members}) >= 2 else []


def emulator_file_summary(files: list[dict], groups: dict | None = None) -> list[str]:
    """What the emulator reads, above its file table, and its categories.

    Counted by slot, as verify --emulator and the gaps page count: raze
    lists every GRP its code accepts under one name, and holding one fills
    the slot. Counted per entry, the page announced 46 missing where 12
    slots are empty. The files the app ships are counted apart: NetherSX2
    said "4 required" for one BIOS and three fonts in its package. A
    required set counts once (`groups`).
    """
    slots = _emulator_slots(files)
    shipped = sum(1 for f in files if comes_with_app(f))
    requirements = _requirements(files, groups)
    in_sets = {id(f) for members in requirements for f in members}
    req_slots = sum(1 for group in slots if any(id(f) in in_sets for f in group))
    req_count = len(requirements)
    optional = len(slots) - req_slots
    hle_count = sum(1 for group in slots if any(f.get("hle_fallback") for f in group))

    # Sentences, one number format: the line read "1,563 files | 164
    # required, 1399 optional | 1563 in repo".
    total = f"**{count_text(len(slots), 'file')}**"
    if sum(len(group) for group in slots) != len(slots):
        total += f" ({sum(len(group) for group in slots):,} accepted versions)"
    line = f"{total}: {req_count:,} required, {optional:,} optional."
    if any(len(members) > 1 for members in requirements):
        line += " Any one file of a required set fills it."
    regional = _regional_set(requirements) or (
        [f for members in requirements for f in members]
        if _regional_choice([f for members in requirements for f in members]) else [])
    if regional:
        # DuckStation takes the BIOS of the game's region: "3 required"
        # read as "get all three".
        line = f"{total}. One of {len(regional):,} is required, for the games' region."
        if optional:
            line += f" {optional:,} {'is' if optional == 1 else 'are'} optional."
    if hle_count:
        line += f" {hle_count:,} {'has' if hle_count == 1 else 'have'} an HLE fallback."
    if shipped:
        line += f" {count_text(shipped, 'more file')} {'comes' if shipped == 1 else 'come'} with the app."
    lines = [line, ""]

    categories = [f.get("category", "bios") for f in files]
    if "game_data" in categories or "bios_zip" in categories:
        cats = [
            f"{categories.count(key):,} {label}"
            for key, label in (
                ("bios", "BIOS"), ("bios_zip", "BIOS ZIPs"), ("game_data", "game data")
            )
            if categories.count(key)
        ]
        lines.extend([f"By kind: {series(cats)}.", ""])
    return lines


def emulator_held_line(files: list[dict], available: Callable[[dict], bool]) -> list[str]:
    """What this collection holds of them, one quiet line under the table:
    a reader comes for what the emulator needs, the project's counts after."""
    slots = _emulator_slots(files)
    if not slots:
        return []
    in_repo = sum(1 for group in slots if any(available(f) for f in group))
    unsourceable = sum(
        1 for group in slots
        if not any(available(f) for f in group) and all(f.get("unsourceable") for f in group)
    )
    held = [f"{in_repo:,} in repo", f"{len(slots) - in_repo - unsourceable:,} missing"]
    if unsourceable:
        held.append(f"{unsourceable:,} unsourceable")
    return [f"<p><small>In this collection: {series(held)}.</small></p>", ""]


def _any_name_folder(profile: dict, entry: dict) -> str:
    """Where the one BIOS goes, as the profile states it, or ""."""
    folder = str(profile.get("bios_directory") or "")
    if not folder:
        path = str(entry.get("path") or "")
        folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
    if not folder:
        return ""
    if profile.get("type") == "standalone":
        # A bare `bios/` is a folder inside the app's own data folder.
        own = ("[the app's data folder](#data-folder)" if profile.get("data_root")
               else "the app's own data folder")
        return f"the {code_span(folder.strip('/'))} folder inside {own}"
    return f"{code_span(folder)}, inside the BIOS folder"


def _any_name_steps(emu_name: str, profile: dict, entry: dict, href: str,
                    name: str = "") -> str:
    """The intro of an emulator that takes one BIOS of any name: get one,
    put it in its folder, any name works.

    An app whose profile names its data folder gets that folder, one tab
    per system it runs on: AetherSX2's step said "inside the app's own
    data folder" while the profile cites Android/data/xyz.aethersx2.android.
    """
    system = system_name((profile.get("systems") or [""])[0])
    example = str(entry.get("name") or "")
    if named_example(example) and href:
        get = f"Download [{code_span(example)}]({href})."
    else:
        get = f"Get one from the {named_system_link(profile['systems'][0], '../')} files."
    steps = [get]
    folders: list[str] = []
    if profile.get("type") == "standalone" and standalone_place(profile, entry):
        steps.append("Put it in this folder:")
        folders = ['<div id="data-folder" class="rb-anchor"></div>', "",
                   *data_folder_block(profile, [entry])]
    else:
        folder = _any_name_folder(profile, entry)
        if folder:
            steps.append(f"Put it in {folder}.")
        folders = _data_folder_intro(name, profile)
    reader = "The app" if profile.get("type") == "standalone" else "The emulator"
    return "\n".join([
        f"{emu_name} needs one {system} BIOS file, any region.",
        "",
        *(f"{number}. {step}" for number, step in enumerate(steps, 1)),
        "",
        *folders,
        *([""] if folders and folders[-1] else []),
        f"Any file name works. {reader} reads what the file holds.",
    ])


def _data_folder_intro(name: str, profile: dict) -> list[str]:
    """Where the app keeps its files, under the intro of a profile that
    names its data folder and takes more than one BIOS of any name."""
    if not profile.get("data_root"):
        return []
    files = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    placed = [f for f in files if standalone_place(profile, f)]
    subject = ("The app" if profile.get("type") == "standalone"
               else "Run on its own, the app")
    lead = (f"{subject} reads its files from this folder:" if placed
            else f"{subject} keeps its data in this folder:")
    return ['<div id="data-folder" class="rb-anchor"></div>', "", lead, "",
            *data_folder_block(profile, files)]


def emulator_intro(emu_name: str, profile: dict, href: str = "", name: str = "") -> str:
    """What the emulator needs, in plain words, from fields every profile has.

    The page opened on a twelve-row table: "Type", "Version", "Checked by".
    DuckStation needs one PlayStation BIOS of any name, and the reader had
    to infer it from the "Files found by" row. ``href`` links the
    collection's copy of the one BIOS an emulator takes under any name,
    and ``name`` is the profile's key.
    """
    entry = any_name_bios(profile)
    if entry is not None:
        return _any_name_steps(emu_name, profile, entry, href, name)
    names: list[str] = []
    for sys_id in profile.get("systems") or []:
        label = system_name(sys_id)
        if label not in names:
            names.append(label)
    # What the app installs itself is no file for the reader to get.
    files = [f for f in profile.get("files") or [] if isinstance(f, dict) and not comes_with_app(f)]
    requirements = _requirements(files, profile.get("groups"))
    required = [f for members in requirements for f in members]
    sentences = []
    if names:
        shown = names if len(names) <= 4 else names[:3] + [f"{len(names) - 3} more systems"]
        sentences.append(f"{emu_name} emulates {series(shown)}.")
    regional = _regional_set(requirements)
    by_region = "" if regional else _regional_choice(required)
    others = len(files) - len(required)
    if regional:
        # DuckStation needs one BIOS of the game's region and accepts 105
        # images: every member of its ps-bios set is marked required, and
        # the page said "105 of them required".
        sentences.append(
            f"It needs one BIOS for the game's region, among the {len(regional):,} it accepts.")
        if others:
            sentences.append(
                f"The {count_text(others, 'other file')} {'is' if others == 1 else 'are'} optional.")
    elif by_region:
        # Three required BIOS of three regions: the page said "3 of them
        # required" and read as "get all of these".
        sentences.append(f"It picks the BIOS for the game's region: {by_region}.")
        if others:
            sentences.append(
                f"The {count_text(others, 'other file')} {'is' if others == 1 else 'are'} optional.")
    elif files:
        sentences.append(
            f"It reads {count_text(len(files), 'file')}, {len(requirements):,} of them required: "
            "without a required file it does not start games."
            if requirements else
            f"It reads {count_text(len(files), 'file')}, none of them required: it starts "
            "games without them."
        )
        if any(len(members) > 1 for members in requirements):
            sentences.append("Any one file of a required set fills it.")
    if required and len(names) > 1:
        sentences.append("A required file is needed only by the machines that use it.")
        if profile.get("found_by") == "content":
            sentences.append("It recognises a file by its contents, so any file name works.")
        if any(f.get("source_ref") for f in files):
            sentences.append("Each file below cites the line of source code that reads it.")
    folder = _data_folder_intro(name, profile) if name else []
    return "\n".join([" ".join(sentences), "", *folder]).strip("\n")


def _regional_choice(required: list[dict], most: int = 6) -> str:
    """The required files as one choice by region, or "" when they are not one.

    Only when every required entry carries a region: and they name at least
    two: region: is the territory the code selects the file for, so the
    reader needs the one of the game's region.
    """
    if not required or len(required) > most or not all(f.get("region") for f in required):
        return ""
    if len({region_words(f["region"]) for f in required}) < 2:
        return ""
    choices = [f"{f.get('name', '')} ({region_words(f['region'], 3)})" for f in required]
    return series(choices, "or")
