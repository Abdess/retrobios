"""Region vocabulary: territories, aliases, labels and their order."""

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
    import difflib

    spelled = raw.strip()
    close = difflib.get_close_matches(spelled.lower(), [*aliases, *regions], n=3, cutoff=0.5)
    hint = f" Close matches: {', '.join(close)}." if close else ""
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
