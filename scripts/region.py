"""Region vocabulary and ordered-priority selection for pack generation.

A file's region: value is the region the emulator code selects it for, not the
region of the dump. Signal standard has no field of its own; it survives only
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

_PARENT: dict[str, str] = {
    member: parent for parent, members in REGION_TREE.items() for member in members
}

REGIONS: frozenset[str] = frozenset({WORLD} | set(REGION_TREE) | set(_PARENT))

# Accepted on the CLI and for legacy profile values.
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
}


def _canonical(raw: str) -> str:
    """Map one token to a canonical region slug."""
    key = raw.strip().lower()
    key = ALIASES.get(key, key)
    if key not in REGIONS:
        raise ValueError(f"unknown region: {raw!r}")
    return key


def comparable(a: str, b: str) -> bool:
    """True when two regions are equal or in a parent/child relation."""
    return a == b or _PARENT.get(a) == b or _PARENT.get(b) == a


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
            # sees the union and is never dropped on ambiguity.
            for key in {path, name} - {""}:
                entry = index.setdefault(
                    key,
                    {"regions": set(), "has_untagged": False, "emulators": []},
                )
                entry["regions"] |= regions
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


def resolve_region_drops(
    groups: dict[str, list[tuple[str, str]]],
    index: dict[str, dict],
    requested: list[str],
) -> set[str]:
    """Destinations to skip for a requested region priority list.

    Per group, an exact/parent regional match beats other regional candidates.
    A world candidate beats unmatched regional fallbacks, while untagged files
    always survive.  If neither a requested nor a world candidate exists, all
    regional candidates survive so filtering can never empty a group.
    """
    if not requested:
        return set()

    keep: set[str] = set()
    drop: set[str] = set()
    for members in groups.values():
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
        if matched:
            best = min(r for r, _destination in matched)
            keep |= {destination for r, destination in matched if r == best}
            drop |= {destination for _r, destination in regional if destination not in keep}
        elif world:
            drop |= {destination for _r, destination in regional}
        else:
            # Preserve every unmatched candidate as a visible fallback.
            keep |= {destination for _r, destination in regional}
    return drop - keep


def fallback_groups(
    groups: dict[str, list[tuple[str, str]]],
    index: dict[str, dict],
    requested: list[str],
) -> list[str]:
    """Group IDs where no candidate matched, so the whole group was kept."""
    if not requested:
        return []
    out: list[str] = []
    for group_id, members in groups.items():
        ranked = _competing_ranks(members, index, requested)
        has_world = any(
            WORLD in lookup_regions(index, destination, name)
            for destination, name in members
        )
        if ranked and not has_world and min(r for r, _ in ranked) == len(requested):
            out.append(group_id)
    return sorted(out)
