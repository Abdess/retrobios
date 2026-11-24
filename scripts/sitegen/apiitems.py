"""The static API items of systems and cores."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable

from model.collection import group_by_manufacturer, manufacturer_slug
from model.database import declared_records, sha1_at
from sitegen.runsections import system_name
from model.profiles import is_emulator
from sitegen.config import SITE_URL
from core.hashing import declared_hash_lists
from sitegen.lookup import site_path
from sitegen.render import card_anchor
from sitegen.runlinks import console_href


def system_index_items(db: dict, coverages: dict, profiles: dict) -> list[dict]:
    """Each system id the platforms and profiles write, reachable by that id.

    api/v1/systems/ is keyed by manufacturer and its consoles by display
    name: a frontend keying by system id (sony-playstation) had no way in.
    The url is the section system_section gives, the one every page links.
    An id with no section of its own (tyrian, scummvm) that holds files
    takes the card of its first file, else the page of the emulator naming
    it: 28 such ids sent their hashes to no page.
    """
    from sitegen.render import system_ids
    from sitegen.runlinks import card_page, system_section

    files = db.get("files") or {}
    held: dict[str, set[str]] = {}
    for coverage in coverages.values():
        for detail in coverage.get("details") or []:
            path = str(detail.get("path") or "")
            sha1 = sha1_at(db, path) if detail.get("status") != "missing" else None
            if sha1:
                held.setdefault(str(detail.get("system", "")), set()).add(sha1)
    for profile in profiles.values():
        if not is_emulator(profile):
            continue
        own = [str(s) for s in profile.get("systems") or []]
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict):
                continue
            ids = ([str(entry["system"])] if entry.get("system")
                   else [str(s) for s in entry.get("systems") or []] or
                   (own if len(own) == 1 else []))
            found = {sha1 for named in declared_records(
                db, declared_hash_lists(entry), entry.get("size")).values()
                for sha1 in named}
            for sys_id in ids:
                held.setdefault(sys_id, set()).update(found)
    manufacturers = {manufacturer_slug(mfr): mfr for mfr in group_by_manufacturer(db)}
    base = urllib.parse.urlsplit(SITE_URL).path
    items = []
    for sys_id in sorted(system_ids(profiles, [c["config"] for c in coverages.values()])):
        section = system_section(sys_id)
        try:
            name = system_name(sys_id)
        except KeyError:
            name = sys_id
        sha1s = sorted(held.get(sys_id, set()) & files.keys())
        manufacturer = manufacturers.get(section[0], "") if section else ""
        url = site_path(console_href(*section)) if section else None
        if url is None and sha1s:
            manufacturer, url = _first_file_place(sys_id, sha1s, files, profiles, card_page)
        # The id's JSON document: api/v1/systems/ is keyed by the manufacturer
        # page, and sony-playstation.json answered 404.
        holder = section[0] if section else manufacturer_slug(manufacturer) if manufacturer else ""
        api = f"{base}api/v1/systems/{holder}.json" if holder else None
        items.append({"id": sys_id, "name": name, "manufacturer": manufacturer,
                      "url": url, "api": api, "sha1": sha1s})
    return items


def _first_file_place(
    sys_id: str, sha1s: list[str], files: dict, profiles: dict,
    card_page: Callable[[str, str], str],
) -> tuple[str, str | None]:
    """(manufacturer, url) of the card of an id's first collection file,
    else of the page of the first emulator naming the id."""
    for sha1 in sha1s:
        parts = str(files[sha1].get("path", "")).split("/")
        if len(parts) >= 3 and parts[0] == "bios":
            page = card_page("/".join(parts), sha1)
            return parts[1], site_path(f"systems/{page}.md#{card_anchor(sha1)}")
    for key in sorted(profiles):
        profile = profiles[key]
        if is_emulator(profile) and sys_id in (profile.get("systems") or []):
            return "", site_path(f"emulators/{key}.md")
    return "", None


def core_index_items(profiles: dict) -> list[dict]:
    """Every name a core goes by, with the profile it designates.

    A frontend knows mednafen_psx_libretro, and api/v1/emulators/ had only
    beetle_psx.json: the reverse index resolve_platform_cores reads, aliases
    included, said once. A name two profiles claim (pcsx2) lists both, the
    one a platform list designates first.
    """
    from model.profiles import preferred_profile, upstream_profile_index

    published = {name for name, p in profiles.items() if is_emulator(p)}
    index = upstream_profile_index(profiles)
    for name, profile in profiles.items():
        target = str(profile.get("alias_of") or "")
        if profile.get("type") == "alias" and target in published:
            index.setdefault(name, set()).add(target)
    items: list[dict] = []
    for name in sorted(index):
        claimants = sorted(index[name] & published)
        preferred = preferred_profile({name: set(claimants)}, name)
        items.extend({"name": name, "profile": profile, "preferred": profile == preferred}
                     for profile in sorted(claimants, key=lambda p: (p != preferred, p)))
    return items
