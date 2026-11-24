"""RetroBat's launcher layer, read from emulatorLauncher's C# generators.

emulatorLauncher decides, per emulator, which file names it looks for in the
BIOS directory, in what order, and what it writes into the emulator's
configuration. The C# is read as text, never compiled: each extractor targets
one construct the generators use and raises LauncherPatternMissing when that
construct is gone, so an upstream rewrite stops the scrape instead of
publishing an empty list.
"""

from __future__ import annotations

from collections.abc import Callable

from resolve.launcherrefs import is_feature_ref, split_ref
from .csharp_source import (
    LauncherPatternMissing,
    Record,
    Source,
)
from .retrobat_arguments import mame, pico8, portable_users, psxmame, xroar
from .retrobat_computers import amiberry, hatari, hatari_libretro, openmsx, winuae
from .retrobat_config_files import (
    ares,
    bizhawk_gb,
    blastem,
    desmume,
    dolphin,
    gsplus,
    jzintv,
    melonds_dsi,
    mesen,
    raine,
    rpcs3,
)
from .retrobat_config_folders import (
    arcadeduck,
    bsyndrome,
    capsimg,
    demul,
    dosbox_copies,
    eka2l1,
    fbneo,
    snes9x,
    tsugaru,
    value_folders,
    xm6pro,
)
from .retrobat_generators import FEATURES, GENERATORS, guarded_writes
from .retrobat_playstation import duckstation, pcsx2, pcsx2_libretro, psx_cascades
from .retrobat_render import option_paths
from .retrobat_xbox import cxbx, xemu, xemu_saves


SOURCE_FILES = (
    f"{GENERATORS}/Amiberry.Generator.cs",
    f"{GENERATORS}/ArcadeDuck.Database.cs",
    f"{GENERATORS}/ArcadeDuck.Generator.cs",
    f"{GENERATORS}/Ares.Generator.cs",
    f"{GENERATORS}/Bizhawk.CoreOptions.cs",
    f"{GENERATORS}/Bizhawk.Generator.cs",
    f"{GENERATORS}/Blastem.Generator.cs",
    f"{GENERATORS}/Citron.Generator.cs",
    f"{GENERATORS}/Cxbx.Generator.cs",
    f"{GENERATORS}/Demul.Generator.cs",
    f"{GENERATORS}/Desmume.Generator.cs",
    f"{GENERATORS}/Dolphin.Generator.cs",
    f"{GENERATORS}/DosBoxPure.Generator.cs",
    f"{GENERATORS}/DosBoxStaging.Generator.cs",
    f"{GENERATORS}/Duckstation.Generator.cs",
    f"{GENERATORS}/Eden.Generator.cs",
    f"{GENERATORS}/Eka2l1.Generator.cs",
    f"{GENERATORS}/Fbneo.Generator.cs",
    f"{GENERATORS}/Flycast.Generator.cs",
    f"{GENERATORS}/GsPlus.Generator.cs",
    f"{GENERATORS}/Hatari.Generator.cs",
    f"{GENERATORS}/Jgenesis.Generator.cs",
    f"{GENERATORS}/Jzintv.Generator.cs",
    f"{GENERATORS}/KegaFusion.Generator.cs",
    f"{GENERATORS}/Kronos.Generator.cs",
    f"{GENERATORS}/LibRetro.CoreOptions.cs",
    f"{GENERATORS}/LibRetro.Generator.cs",
    f"{GENERATORS}/Mame64.Generator.cs",
    f"{GENERATORS}/Mednafen.Generator.cs",
    f"{GENERATORS}/MelonDS.Generator.cs",
    f"{GENERATORS}/Mesen.Generator.cs",
    f"{GENERATORS}/MessSystem.cs",
    f"{GENERATORS}/Mupen64.Generator.cs",
    f"{GENERATORS}/OpenMSX.Generator.cs",
    f"{GENERATORS}/PSXMame.Generator.cs",
    f"{GENERATORS}/Pcsx2.Generator.cs",
    f"{GENERATORS}/Pico8.Generator.cs",
    f"{GENERATORS}/PortsLauncher.Configuration.cs",
    f"{GENERATORS}/Project64.Generator.cs",
    f"{GENERATORS}/Raine.Generator.cs",
    f"{GENERATORS}/Rpcs3.Generator.cs",
    f"{GENERATORS}/Ryujinx.Generator.cs",
    f"{GENERATORS}/SSF.Generator.cs",
    f"{GENERATORS}/ScummVm.Generator.cs",
    f"{GENERATORS}/ShadPS4.Generator.cs",
    f"{GENERATORS}/Snes9x.Generator.cs",
    f"{GENERATORS}/Sudachi.Generator.cs",
    f"{GENERATORS}/Tsugaru.Generator.cs",
    f"{GENERATORS}/Uae.Generator.cs",
    f"{GENERATORS}/Xemu.Generator.cs",
    f"{GENERATORS}/Xm6pro.Generator.cs",
    f"{GENERATORS}/Xroar.Generator.cs",
    f"{GENERATORS}/Yabasanshiro.Generator.cs",
    f"{GENERATORS}/Ymir.Generator.cs",
    f"{GENERATORS}/Yuzu.Generator.cs",
    f"{GENERATORS}/mGBA.Generator.cs",
    FEATURES,
)


EXTRACTORS: tuple[Callable[[dict[str, Source]], list[Record]], ...] = (
    amiberry,
    arcadeduck,
    ares,
    bizhawk_gb,
    blastem,
    bsyndrome,
    capsimg,
    cxbx,
    demul,
    desmume,
    dolphin,
    dosbox_copies,
    duckstation,
    eka2l1,
    fbneo,
    gsplus,
    guarded_writes,
    hatari,
    hatari_libretro,
    jzintv,
    mame,
    melonds_dsi,
    mesen,
    openmsx,
    option_paths,
    pcsx2,
    pcsx2_libretro,
    pico8,
    portable_users,
    psx_cascades,
    psxmame,
    raine,
    rpcs3,
    snes9x,
    tsugaru,
    value_folders,
    winuae,
    xemu,
    xemu_saves,
    xm6pro,
    xroar,
)


def extract_launchers(texts: dict[str, str]) -> list[Record]:
    """Every launcher record the extractors find, in extractor order."""
    missing = [path for path in SOURCE_FILES if path not in texts]
    if missing:
        raise LauncherPatternMissing(missing[0], "source file")
    sources = {path: Source(path, text) for path, text in texts.items()}
    return [
        _choices_apart(record) for extractor in EXTRACTORS for record in extractor(sources)
    ]


def _choices_apart(record: Record) -> Record:
    """The es_features.cfg part of a record's source_ref, moved to choices_from.

    The feature file lists the values a menu option offers. The generator
    writing the choice is the record's evidence, never the list.
    """
    parts = split_ref(str(record["source_ref"]))
    listed = [p for p in parts if is_feature_ref(p)]
    if not listed:
        return record
    code = [p for p in parts if not is_feature_ref(p)]
    if not code:
        raise LauncherPatternMissing(listed[0], "generator code beside the option list")
    moved = {k: v for k, v in record.items() if k != "source_ref"}
    return {**moved, "choices_from": ", ".join(listed), "source_ref": ", ".join(code)}
