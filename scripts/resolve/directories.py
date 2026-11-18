"""Entries that name a directory, expanded to the files the collection holds under it."""

from __future__ import annotations




_directory_members_cache: dict[int, tuple[dict, dict[str, dict[str, str]]]] = {}


def directory_members(db: dict, directory: str) -> dict[str, str]:
    """Files the collection holds under a directory an emulator reads whole.

    Returns {destination: sha1}, each destination starting with the directory
    as the profile writes it. The collection and the destination meet on a
    tail, so the members are the indexed tails that begin with it.

    A generic directory name can sit in two unrelated trees (``voice/``,
    ``data/``). Members that do not share one parent, or a destination two
    contents claim, would merge them into one emulator's directory: nothing
    is returned and the entry stays a reported gap.
    """
    tail = directory.strip("/")
    if not tail:
        return {}
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})
    cached = _directory_members_cache.get(id(by_path_suffix))
    if cached is None or cached[0] is not by_path_suffix:
        cached = (by_path_suffix, {})
        _directory_members_cache[id(by_path_suffix)] = cached
    if tail in cached[1]:
        return cached[1][tail]

    prefix = f"{tail}/"
    infix = f"/{prefix}"
    held: dict[str, list[str]] = {}
    parent: dict[str, str] = {}
    for key, sha1s in by_path_suffix.items():
        if key.startswith(prefix):
            held[key] = sha1s
            continue
        at = key.find(infix)
        if at > 0:
            member = key[at + 1:]
            if len(key[:at]) > len(parent.get(member, "")):
                parent[member] = key[:at]
    held = {
        dest: sha1s for dest, sha1s in held.items() if "/.variants/" not in dest
    }
    one_tree = len({parent.get(dest, "") for dest in held}) <= 1
    one_content = all(len(sha1s) == 1 for sha1s in held.values())
    members = (
        {dest: held[dest][0] for dest in sorted(held)}
        if one_tree and one_content
        else {}
    )
    cached[1][tail] = members
    return members


def expand_directory_entries(
    files: list[dict], db: dict, standalone: bool = False
) -> list[dict]:
    """Replace each ``type: directory`` entry by the files held under it.

    A profile declares the directory its code walks, but what a pack can carry
    is the files. Each member keeps the entry's fields and is pinned to the
    content the collection holds at that destination. A directory nothing
    answers is kept as declared, one gap, and a member the profile also
    names as a file is left to that entry.
    """
    def destination(entry: dict) -> str:
        chosen = entry.get("standalone_path") if standalone else None
        return chosen or entry.get("path") or entry.get("name", "")

    if not any(entry.get("type") == "directory" for entry in files):
        return files
    # A file the profile names itself is left to that entry, in the same
    # build and below the same root: MAME's libretro floppy samples share
    # their path with the standalone tree RetroPie reads below roms/.
    other_build = "libretro" if standalone else "standalone"
    named = {
        (entry.get("root") or "", destination(entry)) for entry in files
        if entry.get("type") != "directory" and entry.get("mode") != other_build
    }
    expanded: list[dict] = []
    for entry in files:
        if entry.get("type") != "directory":
            expanded.append(entry)
            continue
        target = destination(entry)
        # A directory a platform moved (platform_layouts) is the profile's
        # tree at the platform's place: the collection holds it under the
        # layout path, and the platform's folder proves nothing (RetroDECK
        # hands MAME samplepath $bios_path/mame-sa/samples).
        layout = str(entry.get("layout_path") or "") if standalone else ""
        members = directory_members(db, layout) if layout else {}
        if not members:
            # A layout tail two trees answer (MAME's hash/) leaves the
            # platform's own tail.
            layout = ""
            members = directory_members(db, target)
        if layout and layout.strip("/") != target.strip("/"):
            source, place = layout.strip("/") + "/", target.strip("/") + "/"
            members = {
                place + dest[len(source):]: sha1
                for dest, sha1 in members.items() if dest.startswith(source)
            }
        if not members:
            expanded.append(entry)
            continue
        inherited = {
            key: value
            for key, value in entry.items()
            if key not in ("type", "standalone_path", "layout_path")
        }
        expanded.extend(
            {**inherited, "name": dest, "path": dest, "sha1": sha1}
            for dest, sha1 in members.items()
            if (entry.get("root") or "", dest) not in named
        )
    return expanded
