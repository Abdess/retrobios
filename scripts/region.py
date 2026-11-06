"""Region vocabulary and ordered-priority selection for pack generation.

A file's region: value is the region the emulator code selects it for, not the
region of the dump. Signal standard has no field of its own. It survives only
inside slugs whose hardware register fuses the two axes (Saturn SMPC areas).
"""

from __future__ import annotations

WORLD = "world"

# Two levels only: super-region -> member territories.
REGION_TREE: dict[str, frozenset[str]] = {
    "north-america": frozenset({"canada"}),
    "latin-america": frozenset({"brazil", "mexico", "argentina"}),
    "europe": frozenset(
        {
            "uk",
            "france",
            "germany",
            "italy",
            "spain",
            "netherlands",
            "portugal",
            "greece",
            "poland",
            "russia",
            "sweden",
            "norway",
            "denmark",
            "finland",
        }
    ),
    "asia": frozenset(
        {
            "japan",
            "south-korea",
            "china",
            "taiwan",
            "hong-kong",
            "singapore",
            "india",
            "asia-ntsc",
            "asia-pal",
        }
    ),
    "oceania": frozenset({"australia", "new-zealand"}),
}

# Hardware areas that fuse territory and signal standard, with the territories
# the code serves through them. Mednafen's Saturn SMPC area 0x2 is "For TAIWAN
# and PHILIPINES" and its area option offers it as "Taiwan", area 0xA as
# "China" (mednafen/ss/ss.cpp:1119, 2363-2364 in the mednafen_stv port).
# kronos tags the ST-V BIOS epr-19854.ic8 taiwan and mednafen_stv tags it
# asia-ntsc: a request in either spelling has to reach the other.
AREA_TERRITORIES: dict[str, frozenset[str]] = {
    "asia-ntsc": frozenset({"taiwan"}),
    "asia-pal": frozenset({"china"}),
}

_PARENT: dict[str, str] = {
    member: parent for parent, members in REGION_TREE.items() for member in members
}

REGIONS: frozenset[str] = frozenset({WORLD} | set(REGION_TREE) | set(_PARENT))

# Accepted on the CLI and for legacy profile values. Every territory also
# answers to its ISO 3166-1 code: `au` alone was unknown, and the closest
# spelling offered first was `auto`, which means world.
ALIASES: dict[str, str] = {
    "jp": "japan",
    "ntsc-j": "japan",
    "us": "north-america",
    "usa": "north-america",
    "na": "north-america",
    "ntsc-u": "north-america",
    "eu": "europe",
    "pal": "europe",
    "kr": "south-korea",
    "korea": "south-korea",
    "auto": WORLD,
    "gb": "uk",
    "ca": "canada",
    "br": "brazil",
    "mx": "mexico",
    "ar": "argentina",
    "fr": "france",
    "de": "germany",
    "it": "italy",
    "es": "spain",
    "nl": "netherlands",
    "pt": "portugal",
    "gr": "greece",
    "pl": "poland",
    "ru": "russia",
    "se": "sweden",
    "no": "norway",
    "dk": "denmark",
    "fi": "finland",
    "cn": "china",
    "tw": "taiwan",
    "hk": "hong-kong",
    "sg": "singapore",
    "in": "india",
    "au": "australia",
    "nz": "new-zealand",
}


# Slugs a person does not write title-cased: "Asia Ntsc" read as machine text.
LABELS: dict[str, str] = {
    "uk": "UK",
    "asia-ntsc": "Asia (NTSC)",
    "asia-pal": "Asia (PAL)",
}


def label(slug: str) -> str:
    """A region slug in words: north-america as North America."""
    return LABELS.get(slug) or " ".join(word.title() for word in slug.split("-"))


def unknown_region_message(raw: str, aliases: dict[str, str], regions: frozenset[str]) -> str:
    """What to type instead: the closest spellings, then every short form.

    `unknown region: 'uss'` left the user to read the source for `us`.
    """
    import difflib  # noqa: PLC0415

    spelled = raw.strip()
    close = difflib.get_close_matches(spelled.lower(), [*aliases, *regions], n=3, cutoff=0.5)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    return (
        f"unknown region: {spelled}.{hint} Short forms: {', '.join(aliases)}; "
        f"regions: {', '.join(sorted(regions))}"
    )


def _canonical(raw: str) -> str:
    """Map one token to a canonical region slug."""
    key = raw.strip().lower()
    key = ALIASES.get(key, key)
    if key not in REGIONS:
        raise ValueError(unknown_region_message(raw, ALIASES, REGIONS))
    return key


def comparable(a: str, b: str) -> bool:
    """True when two regions are equal, parent and child, or an area and a
    territory it serves."""
    return (
        a == b
        or _PARENT.get(a) == b
        or _PARENT.get(b) == a
        or a in AREA_TERRITORIES.get(b, ())
        or b in AREA_TERRITORIES.get(a, ())
    )


def normalize_declared(raw: str | list | None) -> set[str]:
    """Normalise a profile region: value to canonical slugs."""
    if raw is None:
        return set()
    values = raw if isinstance(raw, list) else [raw]
    return {_canonical(str(v)) for v in values}


def parse_requested(raw: str) -> list[str]:
    """Parse a comma-separated --region value into an ordered priority list."""
    out: list[str] = []
    for part in raw.split(","):
        if not part.strip():
            continue
        slug = _canonical(part)
        if slug not in out:
            out.append(slug)
    if not out:
        raise ValueError("--region requires at least one region")
    return out


def rank(file_regions: set[str], requested: list[str]) -> int:
    """Priority index of a file, lower is better.

    Returns len(requested) when no requested region is comparable, the implicit
    lowest rank that keeps a group from ever being emptied.
    """
    for i, req in enumerate(requested):
        if any(comparable(req, fr) for fr in file_regions):
            return i
    return len(requested)


def region_tag(requested: list[str]) -> str:
    """Pack filename tag for a requested priority list."""
    return "_".join(
        "".join(part.title() for part in slug.split("-")) for slug in requested
    )


def platform_region_index(
    config: dict, profiles: dict, target_cores: set[str] | None = None
) -> dict[str, dict]:
    """The region index of the emulators a platform runs, nothing else.

    Built over every profile, an emulator foreign to the platform voided the
    filter: Pizza Boy SC, an Android app, declares bios_CD_E.bin without a
    region, so the Genesis Plus GX and PicoDrive tags never counted and
    `--region us` kept both CD BIOSes in the RetroArch pack.
    """
    from common import resolve_platform_cores

    cores = resolve_platform_cores(config, profiles, target_cores=target_cores)
    return build_region_index({n: profiles[n] for n in cores if n in profiles})


def build_region_index(profiles: dict) -> dict[str, dict]:
    """Build a region lookup from emulator profiles.

    Keyed by the entry's path when present, by name otherwise.  Untagged
    declarations are recorded as ambiguity evidence: if the same lookup key is
    both tagged and untagged, filtering keeps it instead of inventing a region.
    """
    index: dict[str, dict] = {}
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files") or []:
            if not isinstance(f, dict):
                continue
            try:
                regions = normalize_declared(f.get("region"))
            except ValueError as exc:
                raise ValueError(
                    f"{emu_name}: {f.get('name', '?')}: {exc}"
                ) from exc
            name = f.get("name", "")
            path = f.get("path") or ""
            # Path-keyed so same-named entries stay separate (Dolphin declares
            # three IPL.bin), name-keyed so a candidate identified by name alone
            # sees the union and is never dropped on ambiguity. The standalone
            # layout is a path of its own: GC/EUR/IPL.bin fell through to the
            # bare name and its five-region union, and was never reduced.
            # An alias is another name the core reads for the same file:
            # scph5552.bin, the name beetle_psx also opens for its European
            # BIOS, stayed in a --region jp pack once scph5502.bin went.
            aliases = {str(a) for a in f.get("aliases") or []}
            priority = f.get("priority")
            for key in {path, f.get("standalone_path") or "", name, *aliases} - {""}:
                entry = index.setdefault(
                    key,
                    {"regions": set(), "has_untagged": False, "emulators": [],
                     "priorities": set()},
                )
                entry["regions"] |= regions
                entry["priorities"].add(priority if isinstance(priority, int) else None)
                if not regions:
                    entry["has_untagged"] = True
                if emu_name not in entry["emulators"]:
                    entry["emulators"].append(emu_name)
    return index


def lookup_regions(index: dict[str, dict], destination: str, name: str) -> set[str]:
    """Look a candidate file up in the region index.

    Tries the full destination, then progressively shorter path suffixes, then
    the bare name. Suffix matching bridges a platform entry whose destination
    carries an extra prefix to the profile entry that declares the region.
    """
    if destination:
        entry = index.get(destination)
        if entry:
            return set() if entry.get("has_untagged") else set(entry["regions"])
        parts = destination.split("/")
        for i in range(1, len(parts)):
            entry = index.get("/".join(parts[i:]))
            if entry:
                return set() if entry.get("has_untagged") else set(entry["regions"])
    entry = index.get(name)
    if not entry or entry.get("has_untagged"):
        return set()
    return set(entry["regions"])


def _index_entry(index: dict[str, dict], destination: str, name: str) -> dict | None:
    """The index entry a candidate resolves to, by the lookup_regions order."""
    if destination:
        entry = index.get(destination)
        if entry:
            return entry
        parts = destination.split("/")
        for i in range(1, len(parts)):
            entry = index.get("/".join(parts[i:]))
            if entry:
                return entry
    return index.get(name)


def lookup_priority(index: dict[str, dict], destination: str, name: str) -> int | None:
    """The search rank the code gives a candidate, lower first.

    None when no entry declares one, or when two declarations disagree: a
    rank in doubt cannot decide what to drop.
    """
    entry = _index_entry(index, destination, name)
    priorities = (entry or {}).get("priorities", set())
    if len(priorities) != 1:
        return None
    return next(iter(priorities))


def _competing_ranks(
    members: list[tuple[str, str]],
    index: dict[str, dict],
    requested: list[str],
) -> list[tuple[int, str]]:
    """Rank the members of a group that compete regionally.

    Files with no declared region, and files declared world, are excluded: they
    never compete and never drop.
    """
    ranked: list[tuple[int, str]] = []
    for destination, name in members:
        regions = lookup_regions(index, destination, name)
        if not regions or WORLD in regions:
            continue
        ranked.append((rank(regions, requested), destination))
    return ranked


# Marks the group of a file no system names (extra_region_groups and the
# emulator-mode grouping both build it).
FILE_GROUP = ":file:"


def resolve_region_drops(
    groups: dict[str, list[tuple[str, str]]],
    index: dict[str, dict],
    requested: list[str],
    held: set[str] | None = None,
) -> set[str]:
    """Destinations to skip for a requested region priority list.

    Per group, an exact/parent regional match beats other regional candidates.
    A world candidate beats unmatched regional fallbacks the code does not
    search before it, while untagged files always survive.  If neither a requested nor a world candidate exists, all
    regional candidates survive so filtering can never empty a group.

    ``held`` names the destinations the collection holds. A match it lacks
    never displaces a held file: the American BIOS stays in a Japanese pack
    when the Japanese one is missing, and the missing one stays reported.
    """
    if not requested:
        return set()

    keep: set[str] = set()
    drop: set[str] = set()
    for group_id, members in groups.items():
        if FILE_GROUP in group_id:
            # A file no system names competes with nothing: it drops nothing,
            # and keeping it would veto the group that does decide for the
            # same path. Dolphin's GC/EUR/IPL.bin, alone as a core extra,
            # kept what the GameCube group dropped for --region us. A system
            # holding one file still keeps it: a group is never emptied.
            continue
        regional: list[tuple[int, str]] = []
        world: set[str] = set()
        untagged: set[str] = set()
        for destination, name in members:
            regions = lookup_regions(index, destination, name)
            if not regions:
                untagged.add(destination)
            elif WORLD in regions:
                world.add(destination)
            else:
                regional.append((rank(regions, requested), destination))

        keep |= untagged | world
        if not regional:
            continue
        matched = [(r, destination) for r, destination in regional if r < len(requested)]
        winners, rivals = matched, world
        if held is not None:
            # A missing file answers the request but takes no held file's
            # place: only held files decide what gives way.
            winners = [(r, d) for r, d in matched if d in held]
            rivals = world & held
        if winners:
            best = min(r for r, _destination in winners)
            keep |= {
                destination for r, destination in matched
                if r == best or (r < best and destination not in (held or ()))
            }
            drop |= {destination for _r, destination in regional if destination not in keep}
        elif rivals:
            # A world file beats an unmatched regional one, unless the code
            # provably looks for the regional one first: DuckStation ranks its
            # PS1 images 5 to 50 and its world PS2 images 100, so a request
            # for Brazil would otherwise leave it only the PS2 fallbacks.
            world_ranks = [
                lookup_priority(index, destination, name)
                for destination, name in members
                if destination in rivals
            ]
            known = None not in world_ranks
            best_world = min(world_ranks) if known and world_ranks else None
            for _r, destination in regional:
                name = next(n for d, n in members if d == destination)
                ours = lookup_priority(index, destination, name)
                if best_world is not None and ours is not None and ours < best_world:
                    keep.add(destination)
                else:
                    drop.add(destination)
        else:
            # Preserve every unmatched candidate as a visible fallback.
            keep |= {destination for _r, destination in regional}
    return drop - keep


def fallback_groups(
    groups: dict[str, list[tuple[str, str]]],
    index: dict[str, dict],
    requested: list[str],
) -> list[str]:
    """Group IDs where no candidate matched, so the whole group was kept.

    A world file, or one that declares no region at all, answers every
    region: the C64 kernal VICE loads by default is untagged, and a group
    holding it beside a Japanese and a Swedish kernal does have a BIOS for
    North America. A file no system claims is a group of its own and keeps
    nothing as a fallback: Dolphin's GC/EUR/IPL.bin named the GameCube as
    lacking a North American BIOS the pack carries.
    """
    if not requested:
        return []
    out: list[str] = []
    for group_id, members in groups.items():
        if ":file:" in group_id:
            continue
        ranked = _competing_ranks(members, index, requested)
        served = any(
            not regions or WORLD in regions
            for regions in (
                lookup_regions(index, destination, name)
                for destination, name in members
            )
        )
        if ranked and not served and min(r for r, _ in ranked) == len(requested):
            out.append(group_id)
    return sorted(out)
