"""RetroBat launcher records of the Xbox emulators: xemu and Cxbx-Reloaded."""

from __future__ import annotations

import re

from .csharp_source import Record, Source, _array_at, _strings, _unique, source_ref
from .retrobat_generators import (
    BIOS,
    FEATURES,
    GENERATORS,
    joined,
    launcher_record,
    feature_choices,
)
from model.launcherrecords import join_emulators


def xemu(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Xemu.Generator.cs"]
    features = sources[FEATURES]
    records = []

    mcpx = src.find(
        rf'if \(File\.Exists\(Path\.Combine\({BIOS}, "([^"]+)"\)\)\)\s*(\w+) = Path\.Combine',
        "MCPX boot ROM",
    )
    bootrom = src.find(
        rf'ini\.WriteValue\("([\w.]+)", "(bootrom_path)", "\'" \+ {mcpx.group(2)}',
        "bootrom_path write",
    )
    records.append(
        launcher_record(
            "xemu",
            "standalone",
            "fixed_name",
            [mcpx.group(1)],
            source_ref(
                (
                    src.path,
                    [
                        src.lines(mcpx.start(), mcpx.end()),
                        src.lines(bootrom.start(), bootrom.end()),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"xemu.toml [{bootrom.group(1)}] {bootrom.group(2)}, only if the file exists",
            fails_when_missing=f"{bootrom.group(2)} not written",
        )
    )

    flash = src.find(r'isOptSet\("(xemu_flashrom)"\)', "xemu_flashrom")
    # The flashrom is written outside a Chihiro launch only.
    chihiro_set = src.find(r"(_chihiro) = \(([^;]+)\);", "Chihiro test")
    chihiro_guard = src.find_all(
        rf"if \(!{chihiro_set.group(1)}\)", "flashrom guard", end=flash.start()
    )[-1]
    flash_default = src.find(
        r'ini\.WriteValue\("([\w.]+)", "(flashrom_path)", "\'" \+ Path\.Combine\(flashromPath, "([^"]+)"\)',
        "flashrom default",
        flash.end(),
    )
    choices, choice_lines = feature_choices(features, "xemu", flash.group(1))
    records.append(
        launcher_record(
            "xemu",
            "standalone",
            "core_option",
            _unique([flash_default.group(3), *choices]),
            source_ref(
                (src.path, [
                    src.lines(chihiro_set.start(), chihiro_set.end()),
                    src.lines(chihiro_guard.start(), flash_default.end()),
                ]),
                (features.path, [choice_lines]),
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=(
                f"xemu.toml [{flash_default.group(1)}] {flash_default.group(2)}=<bios>/<value>,"
                f" default {flash_default.group(3)}"
            ),
            fails_when_missing="path written without an existence check",
            depends_on_option=f"{flash.group(1)}, not ({chihiro_set.group(2)})",
        )
    )

    setup = src.find(r"private void SetupChihiroConfiguration\(", "SetupChihiroConfiguration")
    body = src.block_at(setup.end())
    chain = src.find(
        r'string (\w+) = Path\.Combine\(biosPath, ((?:"[^"]+", )*)"([^"]+)"\);\s*'
        r'if \(!File\.Exists\(\1\)\)\s*\1 = Path\.Combine\(biosPath, ((?:"[^"]+", )*)"([^"]+)"\);',
        "Chihiro BIOS chain",
        body[0],
        body[1],
    )
    dirs = [
        "/".join(["bios", *_strings(chain.group(2))]),
        "/".join(["bios", *_strings(chain.group(4))]),
    ]
    bios_write = src.find(
        r'ini\.WriteValue\("([\w.]+)", "(bios_path)"', "Chihiro bios_path", chain.end(), body[1]
    )
    warning = src.find(
        r'else\s*SimpleLogger\.Instance\.Warning\("([^"]+)"\);',
        "Chihiro missing warning",
        bios_write.end(),
        body[1],
    )
    records.append(
        launcher_record(
            "xemu",
            "standalone",
            "names_searched",
            _unique([chain.group(3), chain.group(5)]),
            source_ref((src.path, [src.lines(chain.start(), warning.end())])),
            case_insensitive=True,
            search_dir=", then ".join(dirs),
            passes_to=f"xemu.toml [{bios_write.group(1)}] {bios_write.group(2)}",
            fails_when_missing=f"warning '{warning.group(1)}', {bios_write.group(2)} not written",
        )
    )

    companions = src.find(
        r"foreach \(var f in new\[\] \{", "Chihiro companion files", chain.end(), body[1]
    )
    names, _ = _array_at(src, companions.end() - 1)
    loop = src.block_at(src.block_at(companions.end() - 1)[1])
    records.append(
        launcher_record(
            "xemu",
            "standalone",
            "fixed_name",
            names,
            source_ref((src.path, [(src.line(companions.start()), src.lines(*loop)[1])])),
            case_insensitive=True,
            search_dir="directory of the Chihiro BIOS found",
            passes_to="nothing passed: existence checked only",
            fails_when_missing="warning per missing file",
        )
    )

    board = src.find(
        r'if \((!File\.Exists\(Path\.Combine\(biosDir, "[^"]+"\)\)(?:\s*&&\s*)?)+\)\s*'
        r'SimpleLogger\.Instance\.Warning\("([^"]+)"\);',
        "media board flash names",
        companions.end(),
        body[1],
    )
    records.append(
        launcher_record(
            "xemu",
            "standalone",
            "names_searched",
            re.findall(r'Path\.Combine\(biosDir, "([^"]+)"\)', board.group(0)),
            source_ref((src.path, [src.lines(board.start(), board.end())])),
            case_insensitive=True,
            search_dir="directory of the Chihiro BIOS found",
            passes_to="nothing passed: warning if none exists",
            fails_when_missing=f"warning '{board.group(2)}'",
        )
    )
    return records


def xemu_saves(sources: dict[str, Source]) -> list[Record]:
    """The files the xemu generator keeps below the saves folder.

    An Xbox gets eeprom.bin and xbox_hdd.qcow2 in saves/<system>, written
    from the launcher's own resources when absent, and their paths in
    xemu.toml. A Chihiro keeps chihiro_eeprom.bin there, copied into the
    emulator folder before the run and back after it, and its snapshot
    store.
    """
    src = sources[f"{GENERATORS}/Xemu.Generator.cs"]
    chihiro = src.find(r'(_chihiro) = \(emulator == "([\w-]+)" \|\| system == "(\w+)"\);', "Chihiro switch")
    chihiro_when = f'emulator == "{chihiro.group(2)}" or system == "{chihiro.group(3)}"'
    saves = src.find(
        r'if \(!string\.IsNullOrEmpty\(AppConfig\["saves"\]\) && Directory\.Exists\(AppConfig\.GetFullPath\("saves"\)\)\)'
        r'\s*\{\s*string savePath = Path\.Combine\(AppConfig\.GetFullPath\("saves"\), system\);',
        "Xbox save folder",
    )
    eeprom = src.find(
        r'if \(!File\.Exists\(Path\.Combine\(savePath, "([^"]+)"\)\)\)\s*\{[^{}]*?'
        r'File\.WriteAllBytes\(Path\.Combine\(savePath, "\1"\), Properties\.Resources\.(\w+)\);\s*\}',
        "EEPROM written from resources",
        saves.end(),
    )
    hdd = src.find(
        r'if \(!File\.Exists\(Path\.Combine\(savePath, "([^"]+)"\)\)\)\s*\{[^{}]*?'
        r'File\.WriteAllBytes\(zipFile, Properties\.Resources\.(\w+)\);[^{}]*?Zip\.Extract\(zipFile, savePath\);[^{}]*?\}',
        "hard disk image written from resources",
        eeprom.end(),
    )
    eeprom_key = src.find(
        r'ini\.WriteValue\("([\w.]+)", "(eeprom_path)", "\'" \+ eepromPath', "eeprom_path write"
    )
    hdd_key = src.find(r'ini\.WriteValue\("([\w.]+)", "(hdd_path)", "\'" \+ hddPath', "hdd_path write")
    records = [
        launcher_record(
            "xemu",
            "standalone",
            "fixed_name",
            [eeprom.group(1), hdd.group(1)],
            source_ref(
                (
                    src.path,
                    [
                        src.lines(chihiro.start(), chihiro.end()),
                        src.lines(saves.start(), hdd.end()),
                        src.lines(eeprom_key.start(), eeprom_key.end()),
                        src.lines(hdd_key.start(), hdd_key.end()),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir="saves/<system>",
            passes_to=(
                f"xemu.toml [{eeprom_key.group(1)}] {eeprom_key.group(2)}, {hdd_key.group(2)};"
                f" written from the launcher's {eeprom.group(2)} and {hdd.group(2)} resources"
                " when absent, the disk image unzipped"
            ),
            fails_when_missing="never missing: the launcher writes both",
            depends_on_option=joined("the saves folder is set and exists", f"not ({chihiro_when})"),
        )
    ]

    setup = src.find(r"private void SetupChihiroEeprom\(string path\)", "SetupChihiroEeprom")
    body = src.block_at(setup.end())
    folder = src.find(
        r'string savePath = Path\.Combine\(AppConfig\.GetFullPath\("saves"\), "(\w+)"\);',
        "Chihiro save folder",
        body[0],
        body[1],
    )
    pair = src.find(
        r'_chihiroEeprom = Path\.Combine\(path, "([^"]+)"\);\s*'
        r'_chihiroEepromSave = Path\.Combine\(savePath, "\1"\);',
        "Chihiro EEPROM pair",
        folder.end(),
        body[1],
    )
    save = src.find(r"private void SaveChihiroEeprom\(\)", "SaveChihiroEeprom")
    save_body = src.block_at(save.end())
    records.append(
        launcher_record(
            "xemu, xemu-chihiro",
            "standalone",
            "copies",
            [pair.group(1)],
            source_ref(
                (
                    src.path,
                    [
                        src.lines(chihiro.start(), chihiro.end()),
                        src.statement_span(body),
                        src.statement_span(save_body),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir=f"saves/{folder.group(1)}",
            passes_to=(
                f"<emulator>/{pair.group(1)}, restored when the saved copy is newer or the"
                " emulator folder holds none, copied back after the run"
            ),
            fails_when_missing=False,
            depends_on_option=chihiro_when,
        )
    )

    store = src.find(
        r'string savePath = Path\.Combine\(AppConfig\.GetFullPath\("saves"\), "(\w+)"\);\s*'
        r'if \(!Directory\.Exists\(savePath\)\) try \{ Directory\.CreateDirectory\(savePath\); \} catch \{ \}\s*'
        r'if \(Directory\.Exists\(savePath\)\)\s*'
        r'ini\.WriteValue\("([\w.]+)", "(\w+)", "\'" \+ Path\.Combine\(savePath, "([^"]+)"\)',
        "Chihiro snapshot store",
    )
    records.append(
        launcher_record(
            "xemu, xemu-chihiro",
            "standalone",
            "fixed_name",
            [store.group(4)],
            source_ref((src.path, [src.lines(chihiro.start(), chihiro.end()),
                                   src.lines(store.start(), store.end())])),
            case_insensitive=True,
            search_dir=f"saves/{store.group(1)}",
            passes_to=f"xemu.toml [{store.group(2)}] {store.group(3)}, created by the emulator",
            fails_when_missing=False,
            depends_on_option=chihiro_when,
        )
    )
    return records


# What the Cxbx generator hands each build: the data folder is the one its
# settings.ini sits in (Cxbx-Reloaded Settings::FindSettingsLocation), which
# the launcher writes beside the binary.
CXBX_DATA_FOLDER = "Settings::GetDataLocation"


def cxbx(sources: dict[str, Source]) -> list[Record]:
    """The folder each Cxbx build runs from, and the EEPROM written there.

    The generator picks the emulator folder by core or emulator name, opens
    settings.ini in it, and for an Xbox writes EEPROM.bin into the
    cxbx-reloaded folder from its own resource when absent.
    """
    src = sources[f"{GENERATORS}/Cxbx.Generator.cs"]
    named = src.find_all(
        r'(?:else )?if \(\(core != null && core == "([\w-]+)"\) \|\| '
        r'\(emulator != null && emulator == "\1"\)\)\s*\{\s*path = AppConfig\.GetFullPath\("([\w-]+)"\);',
        "emulator folder by name",
    )
    fallbacks = src.find_all(
        r'if \(string\.IsNullOrEmpty\(path\)\)\s*path = AppConfig\.GetFullPath\("([\w-]+)"\);',
        "default emulator folder",
    )
    settings = src.find(
        r'IniFile\.FromFile\(Path\.Combine\(path, "(settings\.ini)"\)', "settings.ini beside the binary"
    )
    settings_span = src.lines(settings.start(), settings.end())
    passes_to = (
        f"{CXBX_DATA_FOLDER}, the folder holding {settings.group(1)},"
        " which the launcher writes beside the binary"
    )
    records = [
        launcher_record(
            match.group(1),
            "standalone",
            "passes_path",
            [],
            source_ref((src.path, [src.lines(match.start(), match.end()), settings_span])),
            search_dir=f'<AppConfig.GetFullPath("{match.group(2)}")>',
            passes_to=passes_to,
            fails_when_missing=False,
        )
        for match in named
    ]
    first, *rest = fallbacks
    others = "neither core nor emulator is " + " or ".join(f'"{m.group(1)}"' for m in named)
    records.append(
        launcher_record(
            first.group(1),
            "standalone",
            "passes_path",
            [],
            source_ref(
                (
                    src.path,
                    [src.lines(first.start(), first.end()),
                     *(src.lines(m.start(), m.end()) for m in rest), settings_span],
                )
            ),
            search_dir=f'<AppConfig.GetFullPath("{first.group(1)}")>',
            passes_to=passes_to,
            fails_when_missing=False,
            depends_on_option=joined(
                others,
                *(f'<AppConfig.GetFullPath("{m.group(1)}")> when "{first.group(1)}" is not set'
                  for m in rest),
            ),
        )
    )
    records.extend(_cxbx_mount(src, [*(m.group(1) for m in named), first.group(1)]))
    eeprom = src.find(
        r'if \(system == "(\w+)"\)\s*\{\s*string (\w+) = Path\.Combine\(AppConfig\.GetFullPath\("([\w-]+)"\), "([^"]+)"\);'
        r'\s*if \(!File\.Exists\(\2\)\)\s*File\.WriteAllBytes\(\2, Properties\.Resources\.(\w+)\);'
        r'\s*WriteXboxEEPROM\(\2\);\s*\}',
        "EEPROM written from resources",
    )
    records.append(
        launcher_record(
            eeprom.group(3),
            "standalone",
            "fixed_name",
            [eeprom.group(4)],
            source_ref((src.path, [src.lines(eeprom.start(), eeprom.end())])),
            case_insensitive=True,
            search_dir=f'<AppConfig.GetFullPath("{eeprom.group(3)}")>',
            passes_to=(
                f"written from the launcher's {eeprom.group(5)} resource when absent,"
                " then its language set: the emulator reads it from its data folder"
            ),
            fails_when_missing="never missing: the launcher writes it",
            depends_on_option=f'system == "{eeprom.group(1)}"',
        )
    )
    return records


def _cxbx_mount(src: Source, emulators: list[str]) -> list[Record]:
    """What the generator needs to mount an .iso before Cxbx opens it: its
    own xbox-iso-vfs.exe, run from the launcher's folder, and the Dokan 2
    runtime installed on the system."""
    iso = src.find(
        r'if \(Path\.GetExtension\(rom\)\.ToLowerInvariant\(\) != "(\.\w+)"\)\s*return rom;',
        "mount for disc images only",
    )
    vfs = src.find(
        r'string (\w+) = Path\.Combine\(Path\.GetDirectoryName\(typeof\(\w+\)\.Assembly\.Location\), "([^"]+)"\);'
        r'\s*if \(!File\.Exists\(\1\)\)\s*throw new ApplicationException\("([^"]+)"\);',
        "mount tool beside the launcher",
        iso.end(),
    )
    dokan = src.find(
        r'string (\w+) = Environment\.GetEnvironmentVariable\("(\w+)"\);.*?'
        r'\1 = Path\.Combine\(\1, "([^"]+)"\);\s*if \(!File\.Exists\(\1\)\)\s*\{[^{}]*?'
        r'throw new ApplicationException\("([^"]+)"\);\s*\}',
        "Dokan runtime check",
        vfs.end(),
        flags=re.S,
    )
    iso_span = src.lines(iso.start(), iso.end())
    when = f'rom extension "{iso.group(1)}"'
    emulator = join_emulators(emulators)
    return [
        launcher_record(
            emulator,
            "standalone",
            "fixed_name",
            [vfs.group(2)],
            source_ref((src.path, [iso_span, src.lines(vfs.start(), vfs.end())])),
            case_insensitive=True,
            search_dir="<emulatorLauncher folder>",
            passes_to="exec",
            fails_when_missing=vfs.group(3),
            depends_on_option=when,
        ),
        launcher_record(
            emulator,
            "standalone",
            "fixed_name",
            [dokan.group(3)],
            source_ref((src.path, [iso_span, src.lines(dokan.start(), dokan.end())])),
            case_insensitive=True,
            search_dir=f"%{dokan.group(2)}%",
            passes_to=f"nothing passed: checked before {vfs.group(2)} mounts the image",
            fails_when_missing=dokan.group(4),
            depends_on_option=when,
        ),
    ]
