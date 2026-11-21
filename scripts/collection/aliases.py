"""The alternate names platform YAMLs, emulator profiles and known groups give a held content."""

from __future__ import annotations

from dataclasses import dataclass, field

from collection.declared import Declarations, hash_values
from resolve.localfile import variant_base_name


def _primary_names(entries: list) -> set[str]:
    return {str(fe.get("name", "")).lower() for fe in entries if isinstance(fe, dict)}


def _own_aliases(file_entry: dict, primary_names: set[str]) -> list[str]:
    """Aliases that name no other entry of the same profile."""
    name = str(file_entry.get("name", "")).lower()
    return [
        alias for alias in file_entry.get("aliases") or []
        if str(alias).lower() == name or str(alias).lower() not in primary_names
    ]


@dataclass
class _AliasBook:
    """The alternate names collected so far, and what designates a content."""

    files: dict
    md5_to_sha1: dict[str, str]
    name_to_sha1: dict[str, str]
    # The contents held under each name, every copy counted.
    holders: dict[str, set[str]]
    # The files a name designates once case is folded.
    families: dict[str, set[str]]
    # A name only .variants/ copies carry is not a primary's.
    named_primaries: set[str]
    aliases: dict[str, list[dict]] = field(default_factory=dict)

    def add(self, name: str, matched_sha1: str) -> None:
        if not name or name in self.named_primaries:
            return
        if matched_sha1 not in self.aliases:
            self.aliases[matched_sha1] = []
        existing = {a["name"] for a in self.aliases[matched_sha1]}
        if name not in existing:
            self.aliases[matched_sha1].append({"name": name, "path": ""})


def _alias_book(files: dict, copies: dict | None) -> _AliasBook:
    """Index the scanned files by md5, name and folded name."""
    md5_to_sha1 = {}
    name_to_sha1 = {}
    for sha1, entry in files.items():
        md5_to_sha1[entry["md5"]] = sha1
        name_to_sha1[entry["name"]] = sha1
    # The contents held under each name, every copy counted and not only the
    # primary: which copy of identical bytes is primary follows path order.
    # Keyed on primaries alone, project64's 64DD_IPL_v12_JPN.bin stopped
    # naming its content once 64DD_IPL.bin sorted first, and its aliases
    # 64dd_ipl_J.bin and 64DD_IPL_JP.n64 went with it.
    holders: dict[str, set[str]] = {}
    # The files a name designates once case is folded, as the resolver's
    # name step folds it, a primary and its own .variants/ counted as one
    # file. dosbox's SC-55 ROM2.BIN found Galaksija's ROM2.BIN the only
    # exact holder, and its alias ROM2_ST.BIN went to a 4 KiB BASIC ROM,
    # while SC-55's rom2.bin sat under the same folded name.
    families: dict[str, set[str]] = {}

    def _hold(name: str, path: str, sha1: str) -> None:
        holders.setdefault(name, set()).add(sha1)
        directory = path.rpartition("/")[0].removesuffix("/.variants")
        families.setdefault(name.casefold(), set()).add(
            f"{directory}/{variant_base_name(name)}".casefold()
        )

    for sha1, entry in files.items():
        _hold(entry["name"], entry["path"], sha1)
    for sha1, copy_list in (copies or {}).items():
        if sha1 in files:
            for copy in copy_list:
                _hold(copy["name"], copy["path"], sha1)

    # A name only .variants/ copies carry is not a primary's: those copies are
    # the other revisions of whatever the name designates. Retroarch pins
    # bios_E.sms to v1.3, and with the name refused, Genesis Plus GX got the
    # first variant in index order, a 256 KB BIOS, by the name step.
    named_primaries = {
        entry["name"] for entry in files.values() if "/.variants/" not in entry["path"]
    }
    return _AliasBook(files, md5_to_sha1, name_to_sha1, holders, families, named_primaries)


def _platform_aliases(book: _AliasBook, entries: list[dict]) -> None:
    """Register the names platform YAMLs give a held content."""
    for file_entry in entries:
        name = file_entry.get("name", "")
        sha1 = file_entry.get("sha1", "")
        md5 = file_entry.get("md5", "")

        # A zipped_file entry verifies a ROM INSIDE the archive, so its
        # hash describes the member and not the file the name designates.
        # Registering the name against that hash made d2fdc.zip an alias of
        # a loose 256-byte state-machine-16.rom, which three platforms were
        # then served in place of the archive.
        if file_entry.get("zipped_file"):
            continue

        matched = None
        if sha1 and sha1 in book.files:
            matched = sha1
        elif md5 and md5 in book.md5_to_sha1:
            matched = book.md5_to_sha1[md5]

        if matched:
            book.add(name, matched)


def _profile_entry_aliases(
    book: _AliasBook,
    file_entry: dict,
    primary_names: set[str],
    shadowed: list[tuple[str, set[str], list[str]]] | None,
) -> None:
    """Register the aliases one profile entry gives the contents it designates."""
    entry_name = file_entry.get("name", "")
    entry_aliases = _own_aliases(file_entry, primary_names)
    # A profile may accept several revisions: each held one
    # is designated by the entry, none of them by guess.
    matched: set[str] = {
        value for value in hash_values(file_entry.get("sha1"))
        if value in book.files
    }
    matched |= {
        book.md5_to_sha1[value]
        for value in hash_values(file_entry.get("md5"))
        if value in book.md5_to_sha1
    }
    if matched:
        # Proven by content, the profile's own name designates
        # the file whatever the collection calls it.
        entry_aliases.insert(0, entry_name)
    if not entry_aliases:
        return
    if shadowed is not None:
        taken = [
            alias for alias in entry_aliases
            if alias != entry_name and alias in book.named_primaries
        ]
        if taken:
            shadowed.append((entry_name, set(matched), taken))
    held = book.holders.get(entry_name, set())
    if (
        not matched
        and len(held) == 1
        and len(book.families[entry_name.casefold()]) == 1
    ):
        # A name carried by several contents names none of them:
        # quasi88's disk.rom aliases went to whichever
        # disk.rom the scan met last, a Tandy CoCo ROM.
        matched = set(held)
    for sha in sorted(matched):
        for alias_name in entry_aliases:
            book.add(alias_name, sha)


def _profile_aliases(
    book: _AliasBook,
    profiles: list[list[dict]],
    shadowed: list[tuple[str, set[str], list[str]]] | None,
) -> None:
    """Register the aliases emulator YAMLs give (aliases field on file entries)."""
    for entries in profiles:
        # A profile whose entries name each other (dosbox-x opens
        # MT32_CONTROL.ROM and CM32L_CONTROL.ROM alike, so each entry
        # aliases the other) states that ITS slot takes either name.
        # Indexed globally that became evidence for every emulator:
        # ScummVM's MT-32 slot received the CM-32L ROMs.
        primary_names = _primary_names(entries)
        for file_entry in entries:
            _profile_entry_aliases(book, file_entry, primary_names, shadowed)


# Identical content named differently across platforms/cores
KNOWN_ALIAS_GROUPS = [
    # ColecoVision - all these are the same 8KB BIOS
    ["colecovision.rom", "coleco.rom", "BIOS.col", "bioscv.rom"],
    # Game Boy - DMG boot ROM
    ["gb_bios.bin", "dmg_boot.bin", "dmg_rom.bin", "dmg0_rom.bin"],
    # Game Boy Color - CGB boot ROM
    ["gbc_bios.bin", "cgb_boot.bin", "cgb0_boot.bin", "cgb_agb_boot.bin"],
    # Super Game Boy
    ["sgb_bios.bin", "sgb_boot.bin", "sgb.boot.rom"],
    ["sgb2_bios.bin", "sgb2_boot.bin", "sgb2.boot.rom"],
    ["sgb1.program.rom", "SGB1.sfc/program.rom"],
    ["sgb2.program.rom", "SGB2.sfc/program.rom"],
    # Nintendo DS. DraStic opens nds_bios_arm9.bin, nds_bios_arm7.bin
    # and nds_firmware.bin and checks their size only: the collection
    # answers those names with its DS dumps.
    ["NDS_Bios7.bin", "bios7.bin", "nds7.bin", "nds_bios_arm7.bin"],
    ["NDS_Bios9.bin", "bios9.bin", "nds9.bin", "nds_bios_arm9.bin"],
    ["NDS_Lite_Firmware.bin", "nds_firmware.bin"],
    ["dsi_sd_card.bin", "nds_sd_card.bin"],
    # MSX
    ["MSX.ROM", "MSX.rom", "Machines/Shared Roms/MSX.rom"],
    # NEC PC-98
    ["N88KNJ1.ROM", "n88knj1.rom", "quasi88/n88knj1.rom"],
    # Enterprise
    ["zt19uk.rom", "zt19hfnt.rom", "ep128emu/roms/zt19hfnt.rom"],
    # ZX Spectrum
    ["48.rom", "zx48.rom"],
    # SquirrelJME - all JARs are the same
    [
        "squirreljme.sqc",
        "squirreljme.jar",
        "squirreljme-fast.jar",
        "squirreljme-slow.jar",
        "squirreljme-slow-test.jar",
        "squirreljme-0.3.0.jar",
        "squirreljme-0.3.0-fast.jar",
        "squirreljme-0.3.0-slow.jar",
        "squirreljme-0.3.0-slow-test.jar",
    ],
    # Arcade - FBNeo spectrum
    ["spectrum.zip", "fbneo/spectrum.zip", "spec48k.zip"],
]


def collect_all_aliases(
    files: dict,
    declared: Declarations,
    copies: dict | None = None,
    shadowed: list[tuple[str, set[str], list[str]]] | None = None,
) -> dict:
    """Collect alternate filenames from platform YAMLs, profiles, and known aliases.

    Registers alternate names so generate_pack can resolve files stored under different names.
    ``declared`` holds the platform and profile file entries.
    ``copies`` maps a sha1 to the other files the scan found with that content.
    ``shadowed`` receives, per profile entry, its name, the contents its hashes
    designate and the aliases a primary's name already carries.
    """
    book = _alias_book(files, copies)
    _platform_aliases(book, declared.platform_entries)

    # core-info is not read here: it was the only network call of a build
    # that must give the same database offline, and the one name it added
    # (gearcoleco's writer.rom) is a profile entry proven by its sha1, which
    # the profile pass below now registers.

    _profile_aliases(book, declared.profile_entries, shadowed)

    for group in KNOWN_ALIAS_GROUPS:
        matched_sha1 = None
        for name in group:
            if name in book.name_to_sha1:
                matched_sha1 = book.name_to_sha1[name]
                break
        if not matched_sha1:
            continue
        for name in group:
            book.add(name, matched_sha1)

    return book.aliases


def add_declared_aliases(
    files: dict,
    aliases: dict[str, list[dict]],
    shadowed: list[tuple[str, set[str], list[str]]],
    declared: Declarations,
) -> None:
    """Append to the scan's copies every alternate name the declarations give a held content."""
    found = collect_all_aliases(files, declared, aliases, shadowed)
    for sha1, name_list in found.items():
        for alias_entry in name_list:
            if sha1 not in aliases:
                aliases[sha1] = []
            aliases[sha1].append(alias_entry)
