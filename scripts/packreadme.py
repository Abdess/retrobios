"""The notes shipped inside a pack.

A pack has to explain itself offline: what it holds, where each file
goes, and which ones the user has to rename."""

from __future__ import annotations

def _build_readme(
    platform_name: str,
    platform_display: str,
    base_dest: str,
    total_files: int,
    num_systems: int,
    source: str = "full",
    contributors: list[dict] | None = None,
    regions: list[str] | None = None,
    fallback_systems: list[str] | None = None,
    one_per_slot: bool = False,
    undecidable_slots: list[str] | None = None,
    narrowings: list[tuple[str, str]] | None = None,
    system_filter: list[str] | None = None,
) -> str:
    """Build a personalized step-by-step README for each platform pack."""
    narrowings = narrowings or []
    sep = "=" * 50
    header = (
        f"{sep}\n"
        f"  RETROBIOS - {platform_display} BIOS Pack\n"
        f"  {total_files} files for {num_systems} systems\n"
        f"{sep}\n\n"
    )

    guides: dict[str, str] = {
        "retroarch": (
            "INSTALLATION GUIDE\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Run this in a terminal:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  The script auto-detects your RetroArch install and copies\n"
            "  files to the correct location.\n\n"
            "  Option B: Manual (PC)\n"
            "  ---------------------\n"
            "  1. Find your RetroArch system directory:\n"
            "     - RetroArch > Settings > Directory > System/BIOS\n"
            "     - Default: retroarch/system/\n"
            "  2. Extract all files from this archive directly into your system directory\n"
            "  3. Overwrite if asked\n\n"
            "  Option C: Manual (handheld / SD card)\n"
            "  -------------------------------------\n"
            "  Anbernic, Retroid, Miyoo, Trimui, etc.:\n"
            "  1. Connect your SD card to your PC\n"
            "  2. Find the BIOS folder (usually BIOS/ or system/)\n"
            "  3. Extract all files from this archive directly into that folder\n"
            "  4. Eject SD card and reboot your device\n\n"
            "  Common paths by device:\n"
            "    Anbernic (ArkOS/JELOS): BIOS/\n"
            "    Retroid (RetroArch):     RetroArch/system/\n"
            "    Miyoo Mini (Onion OS):   BIOS/\n"
            "    Steam Deck (RetroArch):  ~/.config/retroarch/system/\n\n"
        ),
        "batocera": (
            "INSTALLATION GUIDE\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Open a terminal (F1 from Batocera menu) and run:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  Option B: Manual (network share)\n"
            "  --------------------------------\n"
            "  1. On your PC, open the Batocera network share:\n"
            "     - Windows: \\\\BATOCERA\\share\\bios\\\n"
            "     - Mac/Linux: smb://batocera/share/bios/\n"
            "  2. Extract all files from this archive directly into the share\n"
            "  3. Overwrite if asked\n\n"
            "  Option C: Manual (SD card)\n"
            "  --------------------------\n"
            "  1. Put the SD card in your PC\n"
            "  2. Navigate to /userdata/bios/ on the SHARE partition\n"
            "  3. Extract all files from this archive directly into that folder\n\n"
            "  NOTE: Dreamcast flash memory is named dc_nvmem.bin\n"
            "  (if your setup asks for dc_flash.bin, same file).\n\n"
        ),
        "recalbox": (
            "INSTALLATION GUIDE\n\n"
            "  Option A: Automatic\n"
            "  -------------------\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  Option B: Manual (network share)\n"
            "  --------------------------------\n"
            "  1. On your PC, open the Recalbox network share:\n"
            "     - Windows: \\\\RECALBOX\\share\\bios\\\n"
            "     - Mac/Linux: smb://recalbox/share/bios/\n"
            "  2. Extract all files from this archive directly into the share\n\n"
            "  Option C: Manual (SD card)\n"
            "  --------------------------\n"
            "  1. Put the SD card in your PC\n"
            "  2. Navigate to /recalbox/share/bios/\n"
            "  3. Extract all files from this archive directly into that folder\n\n"
        ),
        "emudeck": (
            "INSTALLATION GUIDE (Steam Deck / Linux)\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Open Konsole (or any terminal) and run:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  The script places BIOS files AND sets up standalone\n"
            "  emulator keys automatically.\n\n"
            "  Option B: Manual\n"
            "  ----------------\n"
            "  1. Open Dolphin file manager\n"
            "  2. Navigate to ~/Emulation/bios/\n"
            "  3. Extract all files from this archive directly into ~/Emulation/bios/\n\n"
            "  STANDALONE EMULATORS (extra step)\n"
            "  Switch and 3DS emulators need keys in specific folders:\n"
            "    prod.keys  -> ~/.local/share/yuzu/keys/\n"
            "    prod.keys  -> ~/.local/share/eden/keys/\n"
            "    prod.keys  -> ~/.config/Ryujinx/system/\n"
            "    aes_keys.txt -> ~/Emulation/bios/citra/keys/\n"
            "  The automatic installer handles this for you.\n\n"
        ),
        "retrodeck": (
            "INSTALLATION GUIDE (Steam Deck / Linux)\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Open Konsole (or any terminal) and run:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  Option B: Manual\n"
            "  ----------------\n"
            "  1. Open Dolphin file manager\n"
            "  2. Show hidden files (Ctrl+H)\n"
            "  3. Navigate to ~/retrodeck/bios/\n"
            "  4. Extract all files from this archive directly into ~/retrodeck/bios/\n\n"
            "  NOTE: RetroDECK uses its own BIOS checker. After\n"
            "  copying, open RetroDECK > Tools > BIOS Checker to\n"
            "  verify everything is detected.\n\n"
        ),
        "retrobat": (
            "INSTALLATION GUIDE (Windows)\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Download and run install.bat from:\n"
            "  https://github.com/Abdess/retrobios/releases\n\n"
            "  Option B: Manual\n"
            "  ----------------\n"
            "  1. Open your RetroBat installation folder\n"
            "  2. Navigate to the bios\\ subfolder\n"
            "     (default: C:\\RetroBat\\bios\\)\n"
            "  3. Extract all files from this archive directly into your bios\\ folder\n"
            "  4. Overwrite if asked\n\n"
        ),
        "bizhawk": (
            "INSTALLATION GUIDE\n\n"
            "  1. Open your BizHawk installation folder\n"
            "  2. Navigate to the Firmware subfolder:\n"
            "     - Windows: BizHawk\\Firmware\\\n"
            "     - Linux: ~/.config/BizHawk/Firmware/\n"
            "  3. Extract all files from this archive directly into your Firmware folder\n"
            "  4. In BizHawk: Config > Paths > Firmware should\n"
            "     point to this folder\n\n"
        ),
        "romm": (
            "INSTALLATION GUIDE (RomM server)\n\n"
            "  1. Locate your RomM library folder\n"
            "  2. Navigate to the bios/ subdirectory\n"
            "  3. Extract all files from this archive directly into that folder\n"
            "  4. Restart the RomM service to detect new files\n\n"
        ),
        "retropie": (
            "INSTALLATION GUIDE (Raspberry Pi)\n\n"
            "  Option A: Via network share\n"
            "  --------------------------\n"
            "  1. On your PC, open: \\\\RETROPIE\\bios\\\n"
            "  2. Extract all files from this archive directly into that folder\n\n"
            "  Option B: Via SSH\n"
            "  -----------------\n"
            "  1. SSH into your Pi: ssh pi@retropie\n"
            "  2. Copy files to ~/RetroPie/BIOS/\n\n"
            "  Option C: Via SD card\n"
            "  ---------------------\n"
            "  1. Put the SD card in your PC\n"
            "  2. Navigate to /home/pi/RetroPie/BIOS/\n"
            "  3. Extract all files from this archive directly into that folder\n\n"
        ),
    }

    # Lakka uses same guide as RetroArch
    guides["lakka"] = guides["retroarch"]

    guide = guides.get(
        platform_name,
        (
            f"INSTALLATION\n\n"
            f"  1. Extract all files from this archive directly into your BIOS directory\n"
            f"  2. Overwrite if asked\n\n"
        ),
    )

    if regions:
        region_help = (
            "  - Wrong region? This pack was filtered. Only the\n"
            "    best-matching BIOS was kept per system. Use the\n"
            "    unfiltered pack to play imports.\n"
        )
    else:
        region_help = (
            "  - Wrong region? Some systems have regional BIOS\n"
            "    variants (USA/EUR/JAP). All are included.\n"
        )
    footer = (
        "TROUBLESHOOTING\n\n"
        "  - Core says BIOS missing? Check the exact filename\n"
        "    and make sure it's in the right subfolder.\n"
        f"{region_help}"
        "  - Need help? https://github.com/Abdess/retrobios/issues\n\n"
        f"{sep}\n"
        f"  https://github.com/Abdess/retrobios\n"
        f"{sep}\n"
    )

    source_info = ""
    if source == "platform":
        source_info = (
            "PACK TYPE: Platform Only\n\n"
            f"  This pack contains only files declared by {platform_display}.\n"
            "  Core extras from emulator profiles are not included.\n"
            "  Use the Full pack for maximum coverage.\n\n"
        )
    elif source == "truth":
        source_info = (
            "PACK TYPE: Ground Truth\n\n"
            "  This pack contains files that emulators actually load,\n"
            "  based on source code analysis of emulator profiles.\n"
            "  Independent of platform scraper accuracy.\n\n"
        )

    region_info = ""
    if regions:
        pretty = ", ".join(
            " ".join(w.title() for w in slug.split("-")) for slug in regions
        )
        region_info = (
            "PACK TYPE: Region Filtered\n\n"
            f"  Region priority: {pretty}\n\n"
            "  Only the best-matching BIOS was kept for each system.\n"
        )
        if fallback_systems:
            listed = "\n".join(f"    {s}" for s in fallback_systems)
            region_info += (
                "\n  These systems have no BIOS in those regions, so all\n"
                "  of theirs were kept:\n"
                f"{listed}\n"
            )
        region_info += (
            "\n  This shrinks the pack. It does not change how cores pick\n"
            "  a BIOS: most already select per region from fixed filename\n"
            "  lists driven by the game's region. Loading imports from\n"
            "  another region may need the unfiltered pack.\n\n"
        )

    slot_info = ""
    if one_per_slot:
        slot_info = (
            "  Where a core declares which BIOS it prefers, only that one was\n"
            "  kept for each system and region. Systems whose cores declare no\n"
            "  order keep all of theirs.\n"
        )
        if undecidable_slots:
            slot_info += (
                f"  {len(undecidable_slots)} slot(s) had no declared order.\n"
            )
        slot_info += "\n"

    narrowed = ""
    labels = [label for _tag, label in narrowings]
    if system_filter:
        labels.append(f"systems {', '.join(system_filter)}")
    if labels:
        listed = "".join(f"    {label}\n" for label in labels)
        narrowed = (
            "PACK TYPE: Narrowed\n\n"
            "  This pack holds fewer files than the full one:\n"
            f"{listed}"
            "\n  The unfiltered pack is the one to use when in doubt.\n\n"
        )

    credits = ""
    if contributors:
        credits = "\nCONTRIBUTORS\n\n"
        for cb in contributors:
            username = cb.get("username", "")
            credits += f"  @{username}\n"
        credits += "\n"

    return (
        header + narrowed + source_info + region_info + slot_info
        + guide + credits + footer
    )

def _build_agnostic_rename_readme(
    destination: str,
    original: str,
    alternatives: list[str],
) -> str:
    """Build a README explaining an agnostic file rename."""
    lines = [
        "This file was renamed for compatibility:",
        f"  {destination} <- {original}",
        "",
    ]
    if alternatives:
        lines.append("All variants included in this pack:")
        for alt in sorted(alternatives):
            lines.append(f"  {alt}")
        lines.append("")
        lines.append(f"To use a different variant, rename it to: {destination}")
    return "\n".join(lines) + "\n"
