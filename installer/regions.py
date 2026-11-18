"""Region names, their aliases and the tree that ranks them."""
from __future__ import annotations

# The region vocabulary of scripts/model/region.py, which this file cannot import.
# A test holds the two copies equal.
WORLD_REGION = "world"
REGION_TREE: dict[str, frozenset] = {
    "north-america": frozenset({"canada"}),
    "latin-america": frozenset({"brazil", "mexico", "argentina"}),
    "europe": frozenset({
        "uk", "france", "germany", "italy", "spain", "netherlands", "portugal",
        "greece", "poland", "russia", "sweden", "norway", "denmark", "finland",
    }),
    "asia": frozenset({
        "japan", "south-korea", "china", "taiwan", "hong-kong", "singapore",
        "india", "asia-ntsc", "asia-pal",
    }),
    "oceania": frozenset({"australia", "new-zealand"}),
}
REGION_ALIASES: dict[str, str] = {
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
    "auto": WORLD_REGION,
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
AREA_TERRITORIES: dict[str, frozenset] = {
    "asia-ntsc": frozenset({"taiwan"}),
    "asia-pal": frozenset({"china"}),
}
_REGION_PARENT = {
    member: parent for parent, members in REGION_TREE.items() for member in members
}
REGIONS = frozenset({WORLD_REGION} | set(REGION_TREE) | set(_REGION_PARENT))


def canonical_region(raw: str) -> str:
    """One region name or alias, spelled the way manifests spell it."""
    key = raw.strip().lower()
    key = REGION_ALIASES.get(key, key)
    if key not in REGIONS:
        import difflib

        close = difflib.get_close_matches(key, [*REGION_ALIASES, *REGIONS], n=3, cutoff=0.5)
        hint = f" Close matches: {', '.join(close)}." if close else ""
        raise ValueError(
            f"unknown region: {raw.strip()}.{hint} "
            f"Short forms: {', '.join(REGION_ALIASES)}. Regions: "
            f"{', '.join(sorted(REGIONS))}"
        )
    return key


def _region_comparable(a: str, b: str) -> bool:
    return (
        a == b
        or _REGION_PARENT.get(a) == b
        or _REGION_PARENT.get(b) == a
        or a in AREA_TERRITORIES.get(b, ())
        or b in AREA_TERRITORIES.get(a, ())
    )


def _region_rank(file_regions: set[str], requested: list[str]) -> int:
    for index, wanted in enumerate(requested):
        if any(_region_comparable(wanted, region) for region in file_regions):
            return index
    return len(requested)


def resolve_regions(values: list[str]) -> list[str]:
    """A region priority list, best first, from names or aliases."""
    chosen: list[str] = []
    for value in values:
        for token in value.split(","):
            if token.strip():
                region = canonical_region(token)
                if region not in chosen:
                    chosen.append(region)
    if values and not chosen:
        raise ValueError("--region needs at least one region")
    return chosen


# Region names as a person writes them, where title case alone is wrong.
_REGION_TITLES = {"asia-ntsc": "Asia (NTSC)", "asia-pal": "Asia (PAL)",
                  "uk": "United Kingdom", WORLD_REGION: "World"}


def region_title(name: str) -> str:
    """north-america as North America, asia-ntsc as Asia (NTSC)."""
    return _REGION_TITLES.get(name) or " ".join(
        word.capitalize() for word in name.split("-"))
