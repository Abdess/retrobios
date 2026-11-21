"""The emulators index: every profile, by classification and system."""

from __future__ import annotations

from model.profiles import is_emulator, unique_emulator_profiles
from sitegen.emulatorcards import named_system_link


def content_check_ceiling(profiles: dict) -> str:
    """How far content checking can reach across every profiled entry."""
    hashed = sized = neither = 0
    for profile in unique_emulator_profiles(profiles).values():
        for f in profile.get("files", []) or []:
            if any(
                f.get(k)
                for k in ("md5", "sha1", "crc32", "sha256", "known_hash_adler32")
            ):
                hashed += 1
            elif any(f.get(k) for k in ("size", "min_size", "max_size")):
                sized += 1
            else:
                neither += 1
    total = hashed + sized + neither
    if not total:
        return ""
    return (
        f"Across every profiled entry, {hashed:,} of {total:,} "
        f"({hashed / total * 100:.0f}%) carry a hash the code checks, "
        f"{sized:,} ({sized / total * 100:.0f}%) only a size, and "
        f"{neither:,} ({neither / total * 100:.0f}%) neither. That last share "
        "is the ceiling of the method: where an emulator validates nothing, "
        "reading its source establishes which file it loads, never whether "
        "the content is the right dump. The provenance field answers that "
        "other question, for the files a dump catalog indexes."
    )


CLS_LABELS = {
    "official_port": "Official ports",
    "community_fork": "Community forks",
    "pure_libretro": "Pure libretro",
    "game_engine": "Game engines",
    "enhanced_fork": "Enhanced forks",
    "frozen_snapshot": "Frozen snapshots",
    "embedded_hle": "Embedded HLE",
    "launcher": "Launchers",
    "unclassified": "Unclassified",
    "other": "Other",
}

# The same classes said of one emulator: its page read "Classification:
# Official ports".
CLS_LABEL_ONE = {
    "official_port": "Official port",
    "community_fork": "Community fork",
    "pure_libretro": "Pure libretro",
    "game_engine": "Game engine",
    "enhanced_fork": "Enhanced fork",
    "frozen_snapshot": "Frozen snapshot",
    "embedded_hle": "Embedded HLE",
    "launcher": "Launcher",
    "unclassified": "Unclassified",
    "other": "Other",
}


INITIAL_DIGITS = "0 to 9"


def emulator_initial(display: str) -> str:
    """The letter an emulator is filed under, in the navigation and on the
    index alike. A name that does not open on a letter goes under "0 to 9"."""
    initial = display[:1].upper()
    return initial if "A" <= initial <= "Z" else INITIAL_DIGITS


def generate_emulators_index(profiles: dict) -> str:
    unique = {
        k: v for k, v in profiles.items()
        if is_emulator(v)
    }
    aliases = {k: v for k, v in profiles.items() if v.get("type") == "alias"}

    by_class: dict[str, list[tuple[str, dict]]] = {}
    for name in sorted(unique.keys()):
        p = unique[name]
        cls = p.get("core_classification", "other")
        by_class.setdefault(cls, []).append((name, p))

    total_files = sum(len(p.get("files", [])) for p in unique.values())

    lines = [
        "# Emulators",
        "",
        "Each page is one emulator: the files it reads, whether it starts games "
        "without them, and the line of its source code that says so. The "
        "kind says how a core relates to the emulator it comes from, which "
        "tells how far its own files can differ.",
        "",
        f"**{len(unique):,}** emulator profiles, **{total_files:,}** files total, **{len(aliases):,}** aliases.",
        "",
        "| Kind | Count | Description |",
        "|------|-------|-------------|",
    ]

    cls_desc = {
        "official_port": "The same authors keep the app and the RetroArch core",
        "community_fork": "Ported to RetroArch by someone else",
        "pure_libretro": "Built for RetroArch, no app of its own",
        "game_engine": "Game engine reimplementation",
        "enhanced_fork": "Fork with added features",
        "frozen_snapshot": "Frozen at an old version",
        "embedded_hle": "Needs no BIOS file: the emulator carries its own",
        "launcher": "Launches an external emulator",
        "other": "Unclassified",
    }

    cls_order = [
        "official_port",
        "community_fork",
        "pure_libretro",
        "game_engine",
        "enhanced_fork",
        "frozen_snapshot",
        "embedded_hle",
        "launcher",
        "other",
    ]

    for cls in cls_order:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        label = CLS_LABELS.get(cls, cls)
        desc = cls_desc.get(cls, "")
        lines.append(f"| {label} | {len(entries)} | {desc} |")
    lines.append("")

    # One section per initial, the groups the navigation draws: its letter
    # links land on the section of the same name.
    by_initial: dict[str, list[tuple[str, dict]]] = {}
    for name, p in unique.items():
        by_initial.setdefault(emulator_initial(str(p.get("emulator", name))), []).append((name, p))
    for initial in sorted(by_initial, key=lambda g: (g != INITIAL_DIGITS, g)):
        lines.extend([
            f"## {initial}",
            "",
            "| Emulator | Kind | Systems | Files |",
            "|--------|------|---------|-------|",
        ])
        entries = sorted(by_initial[initial], key=lambda e: str(e[1].get("emulator", e[0])).casefold())
        for name, p in entries:
            emu_name = p.get("emulator", name)
            cls = p.get("core_classification", "other")
            systems = list(dict.fromkeys(
                named_system_link(s, "../") for s in p.get("systems") or []))
            files = p.get("files", [])
            sys_str = ", ".join(systems[:3])
            if len(systems) > 3:
                sys_str += f" and {len(systems) - 3} more"
            file_count = len(files)
            file_str = f"{file_count:,}" if file_count else "-"
            lines.append(f"| [{emu_name}]({name}.md) | {CLS_LABEL_ONE.get(cls, cls)} | {sys_str} | {file_str} |")
        lines.append("")

    if aliases:
        lines.extend(["## Aliases", ""])
        lines.append("| Core | Points to |")
        lines.append("|------|-----------|")
        for name in sorted(aliases.keys()):
            parent = aliases[name].get(
                "alias_of", aliases[name].get("bios_identical_to", "unknown")
            )
            lines.append(f"| {name} | [{parent}]({parent}.md) |")
        lines.append("")

    return "\n".join(lines) + "\n"
