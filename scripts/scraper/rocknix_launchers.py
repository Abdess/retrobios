"""ROCKNIX's launcher layer, read from its packages at the pinned tag.

ROCKNIX starts each standalone emulator from a shell script and installs a
config with the package. Between a file in /storage/roms/bios and the
emulator, the config names the path (melonDS, xemu, mednafen), the script
searches or links (yabasanshiro, drastic, dolphin), or the emulator is
handed a directory and left to choose (DuckStation, AetherSX2). Several
packages ship one config per device: a record carries `device` only where
the value read differs between them.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass

try:
    from .configgen_launchers import Launcher
    from .shell_launchers import (
        LauncherPatternMissing,
        Link,
        RepoTree,
        Script,
        Setting,
        describe_keys,
        settings,
        source_ref,
    )
except ImportError:
    from configgen_launchers import Launcher
    from shell_launchers import (
        LauncherPatternMissing,
        Link,
        RepoTree,
        Script,
        Setting,
        describe_keys,
        settings,
        source_ref,
    )

ROCKNIX = "projects/ROCKNIX"
DEVICES = f"{ROCKNIX}/devices"
STANDALONE = f"{ROCKNIX}/packages/emulators/standalone"
RETROARCH = f"{ROCKNIX}/packages/emulators/libretro/retroarch"
BIOS_ROOT = "/storage/roms/bios"

Lines = list[tuple[str, set[int]]]


@dataclass
class DeviceConfig:
    """The config file one or more devices install, and the lines that pick it."""

    path: str
    devices: list[str]
    mk_lines: set[int]


def device_configs(
    tree: RepoTree, package: str, file: str, folder: str = "config"
) -> list[DeviceConfig]:
    """Each distinct file package.mk installs as `file` for some device.

    The directory comes from `${PKG_DIR}/<folder>/${DEVICE}/` or from a
    `case ${DEVICE}` naming it. A device whose directory is absent does not
    get the package. A directory that is a symlink resolves to its target.
    """
    mk_path = f"{package}/package.mk"
    mk = Script(mk_path, tree.read(mk_path))
    arms: list[tuple[list[str], str]] = []
    mk_lines: set[int] = set()
    for block in re.finditer(r'case\s+"?\$\{?DEVICE\}?"?\s+in(.*?)\besac\b', mk.text, re.S):
        body = block.group(1)
        if not re.search(rf"CONFIG=|\$\{{PKG_DIR\}}/{folder}/", body):
            continue
        offset = block.start(1)
        for arm in re.finditer(r"^\s*([\w*|]+)\)(.*?);;", body, re.M | re.S):
            chosen = re.search(
                rf'CONFIG="([^"]+)"|\$\{{PKG_DIR\}}/{folder}/([^/\s]+)', arm.group(2)
            )
            if chosen:
                arms.append((arm.group(1).split("|"), chosen.group(1) or chosen.group(2)))
                mk_lines.add(mk.text.count("\n", 0, offset + arm.start(2)) + 1)
        break
    if not arms:
        number, _ = mk.find(
            rf"\$\{{PKG_DIR\}}/{folder}/\$\{{DEVICE\}}/", f"{folder}/${{DEVICE}} copy"
        )
        arms, mk_lines = [(["*"], "${DEVICE}")], {number}
    root = f"{package}/{folder}"
    entries = tree.listdir(root)
    by_path: dict[str, DeviceConfig] = {}
    for device, entry in tree.listdir(DEVICES).items():
        if entry.kind != "dir":
            continue
        arm = next((d for patterns, d in arms if device in patterns or "*" in patterns), None)
        if arm is None:
            continue
        name = device if arm in ("${DEVICE}", "${CONFIG}") else arm
        found = entries.get(name)
        if found is None:
            continue
        if found.kind == "link":
            name = found.target.rstrip("/")
        path = f"{root}/{name}/{file}"
        by_path.setdefault(path, DeviceConfig(path, [], mk_lines)).devices.append(device)
    if not by_path:
        raise LauncherPatternMissing(root, f"{file} for any device")
    return sorted(by_path.values(), key=lambda c: c.path)


def per_device(
    tree: RepoTree,
    configs: list[DeviceConfig],
    mk_path: str,
    read: Callable[[str, str], tuple[object, set[int]]],
) -> list[tuple[str | None, object, Lines]]:
    """Configs grouped by what read() finds in them.

    read(path, text) returns a comparable value and the lines it comes from.
    One group gives one result without a device. Otherwise each group names
    its devices, in the order of the devices directory.
    """
    groups: dict[object, tuple[list[str], Lines]] = {}
    for config in configs:
        value, lines = read(config.path, tree.read(config.path))
        devices, refs = groups.setdefault(value, ([], []))
        devices.extend(config.devices)
        refs.append((config.path, lines))
    mk_lines = set().union(*(c.mk_lines for c in configs))
    if len(groups) == 1:
        ((value, (_, refs)),) = groups.items()
        return [(None, value, [*refs, (mk_path, mk_lines)])]
    order = list(tree.listdir(DEVICES))
    return [
        (", ".join(sorted(devices, key=order.index)), value, [*refs, (mk_path, mk_lines)])
        for value, (devices, refs) in sorted(
            groups.items(), key=lambda g: min(order.index(d) for d in g[1][0])
        )
    ]


def _file_under(value: str, root: str) -> bool:
    return value.startswith(root.rstrip("/") + "/")


@dataclass(frozen=True)
class FixedPaths:
    """Keys of a config that name a file under one directory."""

    keys: tuple[tuple[str, str], ...]
    names: tuple[str, ...]
    search_dir: str


def fixed_paths(
    found: list[Setting], keys: list[tuple[str, str]], path: str
) -> tuple[FixedPaths, set[int]]:
    """The values of keys, as names relative to the directory they share."""
    by_key = {(s.section, s.key): s for s in found}
    missing = [k for k in keys if k not in by_key]
    if missing:
        raise LauncherPatternMissing(path, f"key {missing[0][1]}")
    values = [by_key[k].value for k in keys if by_key[k].value]
    lines = {by_key[k].line for k in keys}
    if not values:
        return FixedPaths(tuple(keys), (), ""), lines
    folder = posixpath.commonpath([posixpath.dirname(v) for v in values])
    names = tuple(posixpath.relpath(v, folder) for v in values)
    return FixedPaths(tuple(keys), names, folder), lines


def bios_keys(tree: RepoTree, paths: list[str], root: str = BIOS_ROOT) -> list[tuple[str, str]]:
    """Keys whose value is a file under root in at least one of the configs."""
    keys: list[tuple[str, str]] = []
    for path in paths:
        for setting in settings(tree.read(path)):
            key = (setting.section, setting.key)
            if _file_under(setting.value, root) and key not in keys:
                keys.append(key)
    if not keys:
        raise LauncherPatternMissing(paths[0], f"key naming a file under {root}")
    return keys


def config_records(
    tree: RepoTree,
    emulator: str,
    package: str,
    file: str,
    passes_to_suffix: str = "",
    depends_on_option: str | None = None,
) -> list[Launcher]:
    """fixed_name records for the bios paths of a config installed per device."""
    configs = device_configs(tree, package, file)
    keys = bios_keys(tree, [c.path for c in configs])
    name = posixpath.basename(file)

    def read(path: str, text: str) -> tuple[object, set[int]]:
        return fixed_paths(settings(text), keys, path)

    records = []
    for device, value, refs in per_device(tree, configs, f"{package}/package.mk", read):
        assert isinstance(value, FixedPaths)
        described = describe_keys(name, value.keys)
        records.append(
            Launcher(
                emulator=emulator,
                build="standalone",
                kind="fixed_name",
                names=list(value.names),
                source_ref=source_ref(refs),
                search_dir=value.search_dir or None,
                passes_to=(
                    (described + passes_to_suffix) if value.names else f"{described} left empty"
                ),
                device=device,
                depends_on_option=depends_on_option,
            )
        )
    return records


def retroarch(tree: RepoTree) -> list[Launcher]:
    """system_directory of the retroarch.cfg each device installs."""
    configs = device_configs(tree, RETROARCH, "retroarch.cfg", folder="sources")
    wanted = ("system_directory", "systemfiles_in_content_dir")

    def read(path: str, text: str) -> tuple[object, set[int]]:
        found = {s.key: s for s in settings(text) if s.key in wanted}
        if "system_directory" not in found:
            raise LauncherPatternMissing(path, "system_directory")
        return tuple((k, found[k].value) for k in wanted if k in found), {
            s.line for s in found.values()
        }

    records = []
    for device, value, refs in per_device(tree, configs, f"{RETROARCH}/package.mk", read):
        assert isinstance(value, tuple)
        values = dict(value)
        records.append(
            Launcher(
                emulator="retroarch",
                build="libretro",
                kind="passes_path",
                names=[],
                source_ref=source_ref(refs),
                search_dir=values["system_directory"],
                passes_to="retroarch.cfg " + ", ".join(f'{k} = "{v}"' for k, v in value),
                device=device,
            )
        )
    return records


def amiberry(tree: RepoTree) -> list[Launcher]:
    """The A500 or A1200 config, chosen by the game name, then the kickstarts link."""
    package = f"{STANDALONE}/amiberry"
    script = Script(
        f"{package}/scripts/start_amiberry.sh", tree.read(f"{package}/scripts/start_amiberry.sh")
    )
    test_line, test = script.find(r"grep -E '([^']+)'", "machine choice by game name")
    then_line, then = script.find(
        r"cp \S+/(\w+-default\.uae)", "config copied for a match", test_line
    )
    else_line, _ = script.find(r"^\s*else\b", "else of the machine choice", then_line)
    other_line, other = script.find(
        r"cp \S+/(\w+-default\.uae)", "config copied otherwise", else_line
    )
    sed_line, sed = script.find(
        r'sed -i "s#(@\w+@)#\$\{(\w+)\}#g"', "placeholder substitution", other_line
    )
    used: set[int] = {test_line, then_line, else_line, other_line, sed_line}
    root = script.expand("${" + sed.group(2) + "}", sed_line, used)
    records = []
    for config, condition in (
        (then.group(1), f"game name matches {test.group(1)}"),
        (other.group(1), f"game name does not match {test.group(1)}"),
    ):
        path = f"{package}/config/conf/{config}"
        found = [
            Setting(s.section, s.key, s.value.replace(sed.group(1), root), s.line)
            for s in settings(tree.read(path))
        ]
        keys = [(s.section, s.key) for s in found if _file_under(s.value, root)]
        if not keys:
            raise LauncherPatternMissing(path, f"key naming a file under {sed.group(1)}")
        value, lines = fixed_paths(found, keys, path)
        slot = re.fullmatch(r"Amiga(\w+)-default\.uae", config)
        records.append(
            Launcher(
                emulator="amiberry",
                build="standalone",
                kind="fixed_name",
                names=list(value.names),
                source_ref=source_ref([(script.path, used), (path, lines)]),
                slot=slot.group(1) if slot else config,
                search_dir=value.search_dir,
                passes_to=f"{describe_keys(config, value.keys)} (amiberry -f)",
                depends_on_option=condition,
            )
        )
    mk = Script(f"{package}/package.mk", tree.read(f"{package}/package.mk"))
    links = mk.links(BIOS_ROOT, fixed={"INSTALL": ""})
    if not links:
        raise mk.missing(f"ln -s of {BIOS_ROOT}")
    records.extend(link_record("amiberry", mk, link) for link in links)
    # The script copies the installed folder, links included, to the one it
    # enters before it runs amiberry: the kickstarts link is read there.
    copy_line, copy = script.find(r"cp -rf? (\S+) \$\{?(\w+)\}?\s*$", "copy of the installed folder")
    cd_line, cd = script.find(r"^\s*cd \$\{?(\w+)\}?\s*$", "working directory")
    if cd.group(1) != copy.group(2):
        raise LauncherPatternMissing(script.path, "cd into the copied folder")
    entered: set[int] = {cd_line}
    folder = script.expand("${" + cd.group(1) + "}", cd_line, entered)
    records.append(Launcher(
        emulator="amiberry", build="standalone", kind="passes_path", names=[],
        source_ref=source_ref([(script.path, entered)]),
        search_dir=folder, passes_to=f"working directory of {script.path.rsplit('/', 1)[-1]}",
    ))
    installed = copy.group(1).rstrip("/")
    for link in links:
        if not link.link.startswith(installed + "/"):
            continue
        copied = folder + link.link[len(installed):]
        records.append(Launcher(
            emulator="amiberry", build="standalone", kind="links", names=list(link.names),
            source_ref=source_ref([(mk.path, link.lines), (script.path, {copy_line} | entered)]),
            search_dir=link.bios_side,
            passes_to=f"symlink {copied} -> {link.target}, copied with {installed}",
        ))
    return records


def link_record(
    emulator: str,
    script: Script,
    link: Link,
    case_insensitive: bool | None = None,
    fails_when_missing: bool | str = False,
) -> Launcher:
    return Launcher(
        emulator=emulator,
        build="standalone",
        kind="links",
        names=list(link.names),
        source_ref=source_ref([(script.path, link.lines)]),
        expands=link.expands or None,
        search_dir=link.bios_side,
        passes_to=f"symlink {link.link} -> {link.target}",
        case_insensitive=case_insensitive,
        fails_when_missing=fails_when_missing,
    )


def hatari(tree: RepoTree) -> list[Launcher]:
    package = f"{STANDALONE}/hatarisa"
    # The script is named after the package's binary: start_hatari.sh became
    # start_hatarisa.sh (2e7041d273), so it is found, not spelled.
    starts = sorted(
        name for name in tree.listdir(f"{package}/scripts")
        if name.startswith("start_") and name.endswith(".sh")
    )
    if len(starts) != 1:
        raise LauncherPatternMissing(f"{package}/scripts", "one start script")
    script = Script(f"{package}/scripts/{starts[0]}", tree.read(f"{package}/scripts/{starts[0]}"))
    copy_line, copy = script.find(r"cp \S+/([\w-]+\.cfg) ", "default config copy")
    run_line, _ = script.find(r"--configfile", "--configfile", copy_line)
    path = f"{package}/config/conf/{copy.group(1)}"
    found = settings(tree.read(path))
    keys = [(s.section, s.key) for s in found if _file_under(s.value, BIOS_ROOT)]
    if not keys:
        raise LauncherPatternMissing(path, f"key naming a file under {BIOS_ROOT}")
    value, lines = fixed_paths(found, keys, path)
    return [
        Launcher(
            emulator="hatari",
            build="standalone",
            kind="fixed_name",
            names=list(value.names),
            source_ref=source_ref([(path, lines), (script.path, {copy_line, run_line})]),
            search_dir=value.search_dir,
            passes_to=f"{describe_keys(copy.group(1), value.keys)} (--configfile)",
        )
    ]


def melonds(tree: RepoTree) -> list[Launcher]:
    package = f"{STANDALONE}/melonds-sa"
    script = Script(
        f"{package}/scripts/start_melonds.sh", tree.read(f"{package}/scripts/start_melonds.sh")
    )
    enable_line, _ = script.find(r"ExternalBIOSEnable=1", "ExternalBIOSEnable=1")
    tests = [
        (number, found)
        for number, line in script.code()
        if number < enable_line and (found := re.search(r'if \[ "\$(\w+)" = "(\w+)" \]', line))
    ]
    if not tests:
        raise script.missing("test that enables the external BIOS")
    test_line, test = tests[-1]
    setting_line, setting = script.find(
        rf"^\s*{test.group(1)}=\$\(get_setting (\w+) ", f"setting read into {test.group(1)}"
    )
    condition = f"{setting.group(1)} = {test.group(2)} sets ExternalBIOSEnable=1, otherwise 0"
    records = config_records(tree, "melonds", package, "melonDS.ini", depends_on_option=condition)
    for record in records:
        record.source_ref += (
            f", {source_ref([(script.path, {setting_line, test_line, enable_line})])}"
        )
    return records


def dsperate(tree: RepoTree) -> list[Launcher]:
    package = f"{STANDALONE}/dsperate-sa"
    script = Script(
        f"{package}/scripts/start_dsperate.sh", tree.read(f"{package}/scripts/start_dsperate.sh")
    )
    run_line, _ = script.find(r"/usr/bin/dsperate --config ", "dsperate --config")
    records = config_records(tree, "dsperate", package, "dsperate.ini", " (--config)")
    for record in records:
        record.source_ref += f", {source_ref([(script.path, {run_line})])}"
    return records


def xemu(tree: RepoTree) -> list[Launcher]:
    package = f"{STANDALONE}/xemu-sa"
    script = Script(
        f"{package}/scripts/start_xemu.sh", tree.read(f"{package}/scripts/start_xemu.sh")
    )
    copy_line, _ = script.find(
        r'cp -r "\$\{SOURCE_DIR\}/\$\{XEMU_INI\}"', "xemu.toml copy at launch"
    )
    records = config_records(tree, "xemu", package, "xemu.toml", " (copied at each launch)")
    for record in records:
        record.source_ref += f", {source_ref([(script.path, {copy_line})])}"
    return records


def nanoboyadvance(tree: RepoTree) -> list[Launcher]:
    package = f"{STANDALONE}/nanoboyadvance-sa"
    path = f"{package}/config/config.toml"
    found = settings(tree.read(path))
    keys = [(s.section, s.key) for s in found if _file_under(s.value, BIOS_ROOT)]
    if not keys:
        raise LauncherPatternMissing(path, f"key naming a file under {BIOS_ROOT}")
    value, lines = fixed_paths(found, keys, path)
    mk_path = f"{package}/package.mk"
    mk_line, _ = Script(mk_path, tree.read(mk_path)).find(
        r"config/config\.toml", "config.toml install"
    )
    return [
        Launcher(
            emulator="nanoboyadvance",
            build="standalone",
            kind="fixed_name",
            names=list(value.names),
            source_ref=source_ref([(path, lines), (mk_path, {mk_line})]),
            search_dir=value.search_dir,
            passes_to=describe_keys("config.toml", value.keys),
        )
    ]


def mednafen(tree: RepoTree) -> list[Launcher]:
    """The firmware keys of mednafen.template, one record per module."""
    package = f"{STANDALONE}/mednafen"
    path = f"{package}/config/common/mednafen.template"
    found = settings(tree.read(path), separator=" ")
    folder = next((s for s in found if s.key == "filesys.path_firmware"), None)
    if folder is None:
        raise LauncherPatternMissing(path, "filesys.path_firmware")
    pattern = re.compile(r"(\w+)\.(\w*bios\w*|ggrom|cart\.\w+_path)")
    firmware = [s for s in found if pattern.fullmatch(s.key) and s.value and not s.value.isdigit()]
    if not firmware:
        raise LauncherPatternMissing(path, "firmware keys")
    script_path = f"{package}/scripts/start_mednafen.sh"
    script = Script(script_path, tree.read(script_path))
    gen_line, _ = script.find(r"mednafen_gen_config\.sh", "config generation")
    test_line, _ = script.find(
        r'if \[ ! -f "\$MEDNAFEN_HOME/mednafen\.cfg" \]', "mednafen.cfg test"
    )
    modules: dict[str, list[Setting]] = {}
    for setting in firmware:
        modules.setdefault(setting.key.split(".", 1)[0], []).append(setting)
    return [
        Launcher(
            emulator="mednafen",
            build="standalone",
            kind="fixed_name",
            names=list(dict.fromkeys(s.value for s in group)),
            source_ref=source_ref(
                [
                    (path, {folder.line, *(s.line for s in group)}),
                    (script_path, {test_line, gen_line}),
                ]
            ),
            slot=module,
            search_dir=folder.value,
            passes_to="mednafen.cfg " + ", ".join(s.key for s in group),
        )
        for module, group in modules.items()
    ]


def yabasanshiro(tree: RepoTree) -> list[Launcher]:
    package = f"{STANDALONE}/yabasanshiro-sa"
    script = Script(
        f"{package}/scripts/start_yabasanshiro.sh",
        tree.read(f"{package}/scripts/start_yabasanshiro.sh"),
    )
    option_line, option = script.find(r"=\$\(get_setting (\w+) ", "BIOS option")
    test_line, test = script.find(r'if \[ "\$\w+" = (\w+) \]', "BIOS option test", option_line)
    loop = next((lp for lp in script.loops() if lp.start > test_line), None)
    if loop is None:
        raise script.missing("loop over BIOS names")
    find_line, find = script.find(
        rf"\$\(find (\S+) -name \$\{{{loop.var}\}}", "find of each name", loop.start, loop.end
    )
    flag_line, flag = script.find(
        r'="(-\w) \$\{\w+\}"', "flag the found path is passed with", find_line, loop.end
    )
    break_line, _ = script.find(r"^\s*break\b", "break on the first found", flag_line, loop.end)
    return [
        Launcher(
            emulator="yabasanshiro",
            build="standalone",
            kind="names_searched",
            names=loop.items,
            source_ref=source_ref(
                [(script.path, {option_line, test_line, *range(loop.start, loop.end + 1)})]
            ),
            case_insensitive=False,
            search_dir=f"{find.group(1)} (recursive)",
            passes_to=f"yabasanshiro {flag.group(1)} <first path found>",
            fails_when_missing=False,
            depends_on_option=f"{option.group(1)} = {test.group(1)} (game, then platform)",
        )
    ]


def directory_records(
    tree: RepoTree,
    emulator: str,
    package: str,
    file: str,
    folder_key: tuple[str, str],
    file_keys: tuple[tuple[str, str], ...],
) -> list[Launcher]:
    """scans_dir records: the config hands a directory and leaves the file keys empty."""
    configs = device_configs(tree, package, file)
    name = posixpath.basename(file)

    def read(path: str, text: str) -> tuple[object, set[int]]:
        found = {(s.section, s.key): s for s in settings(text)}
        if folder_key not in found:
            raise LauncherPatternMissing(path, f"[{folder_key[0]}] {folder_key[1]}")
        set_files = [k for k in file_keys if k in found and found[k].value]
        if set_files:
            raise LauncherPatternMissing(path, f"empty [{set_files[0][0]}] {set_files[0][1]}")
        lines = {found[k].line for k in (folder_key, *file_keys) if k in found}
        return found[folder_key].value, lines

    unset = describe_keys("", file_keys).strip()
    records = []
    for device, folder, refs in per_device(tree, configs, f"{package}/package.mk", read):
        passes = f"{name} [{folder_key[0]}] {folder_key[1]} = {folder}, {unset} unset"
        records.append(
            Launcher(
                emulator=emulator,
                build="standalone",
                kind="scans_dir",
                names=[],
                source_ref=source_ref(refs),
                search_dir=folder,
                passes_to=passes,
                device=device,
            )
        )
    return records


def duckstation(tree: RepoTree) -> list[Launcher]:
    return directory_records(
        tree,
        "duckstation",
        f"{STANDALONE}/duckstation-sa",
        "settings.ini",
        ("BIOS", "SearchDirectory"),
        (("BIOS", "PathNTSCU"), ("BIOS", "PathNTSCJ"), ("BIOS", "PathPAL")),
    )


def armsx2(tree: RepoTree) -> list[Launcher]:
    return directory_records(
        tree,
        "armsx2",
        f"{STANDALONE}/armsx2-sa",
        "ARMSX2/inis/PCSX2.ini",
        ("Folders", "Bios"),
        (("Filenames", "BIOS"),),
    )


# Start scripts whose ln -s commands put a BIOS path where the emulator reads.
def pico8(tree: RepoTree) -> list[Launcher]:
    """The PICO-8 binary start_pico8.sh executes, outside /storage/roms/bios.

    The script picks the binary by HW_ARCH, pico8_64 on aarch64 and
    pico8_dyn on any other, and runs it from GAME_DIR, or from
    GAME_DIR/${HW_ARCH} when that folder exists.
    """
    path = f"{STANDALONE}/pico-8/scripts/start_pico8.sh"
    script = Script(path, tree.read(path))
    game_line, game = script.find(r'^\s*GAME_DIR="([^"$]+)"', "GAME_DIR assignment")
    case_line, _ = script.find(r"^\s*case \$\{HW_ARCH\} in", "case on HW_ARCH")
    arch_line, arch = script.find(r"^\s*(\w+)\)", "HW_ARCH branch", case_line + 1)
    first_line, first = script.find(r'STATIC_BIN="([^"$]+)"', "binary of the first branch", arch_line)
    other_line, _ = script.find(r"^\s*\*\)", "default HW_ARCH branch", first_line)
    rest_line, rest = script.find(r'STATIC_BIN="([^"$]+)"', "binary of the default branch", other_line)
    sub_line, _ = script.find(
        r'if \[ -d "\$\{GAME_DIR\}/\$\{HW_ARCH\}" \]', "per-architecture launch folder"
    )
    end_line, _ = script.find(r"^\s*fi\b", "end of the launch folder test", sub_line)
    run_line, _ = script.find(r"^\s*\$\{LAUNCH_DIR\}/\$\{STATIC_BIN\} ", "binary run")
    return [
        Launcher(
            emulator="pico-8",
            build="standalone",
            kind="fixed_name",
            names=[first.group(1), rest.group(1)],
            source_ref=source_ref([(path, {
                game_line, case_line, arch_line, first_line, other_line, rest_line,
                *range(sub_line, end_line + 1), run_line,
            })]),
            search_dir=game.group(1).rstrip("/"),
            passes_to="exec",
            fails_when_missing=False,
            depends_on_option=(
                f"HW_ARCH {arch.group(1)} runs {first.group(1)}, any other {rest.group(1)}, "
                f"from {game.group(1).rstrip('/')}/${{HW_ARCH}} when that folder exists"
            ),
        )
    ]


LINK_SCRIPTS = (
    ("drastic", f"{STANDALONE}/drastic-sa/scripts/start_drastic.sh"),
    ("dolphin", f"{STANDALONE}/dolphin-sa/scripts/start_dolphin_gc.sh"),
    ("flycast", f"{STANDALONE}/flycast-sa/scripts/start_flycast.sh"),
    ("cemu", f"{STANDALONE}/cemu-sa/scripts/start_cemu.sh"),
    ("rpcs3", f"{STANDALONE}/rpcs3-sa/scripts/start_rpcs3.sh"),
)


def links(tree: RepoTree) -> list[Launcher]:
    records = []
    for emulator, path in LINK_SCRIPTS:
        script = Script(path, tree.read(path))
        found = script.links(BIOS_ROOT)
        if not found:
            raise script.missing(f"ln -s of a path under {BIOS_ROOT}")
        for link in found:
            guard = _existence_guard(script, link)
            if guard is not None:
                link.lines.add(guard)
            records.append(
                link_record(
                    emulator,
                    script,
                    link,
                    case_insensitive=False if guard is not None else None,
                    fails_when_missing=False,
                )
            )
    return records


# Packages whose build patch replaces the function an emulator resolves a
# directory with by a fixed path: ROCKNIX's Flycast returns
# /storage/roms/dreamcast/data as its data directory, which start_flycast.sh
# then links to the BIOS tree.
DIRECTORY_PATCHES = (
    ("flycast", f"{STANDALONE}/flycast-sa/patches/000-conf-dir.patch", "find_user_data_dir"),
)


def patched_directories(tree: RepoTree) -> list[Launcher]:
    records = []
    for emulator, path, function in DIRECTORY_PATCHES:
        lines = tree.read(path).splitlines()
        target = next(
            (line[len("+++ b/"):] for line in lines if line.startswith("+++ b/")), None
        )
        start = next(
            (n for n, line in enumerate(lines, 1) if re.search(rf"\b{function}\(\)", line)),
            None,
        )
        returned = None
        if target is not None and start is not None:
            returned = next(
                (
                    (n, match.group(1))
                    for n, line in enumerate(lines[start:], start + 1)
                    if (match := re.match(r'^\+\s*return "(/[^"]+)";', line))
                ),
                None,
            )
        if returned is None:
            raise LauncherPatternMissing(path, f"{function}() patched to return a fixed path")
        number, directory = returned
        records.append(Launcher(
            emulator=emulator,
            build="standalone",
            kind="passes_path",
            names=[],
            source_ref=source_ref([(path, {start, number})]),
            search_dir=directory.rstrip("/"),
            passes_to=f"{function}() in {target} returns it",
            fails_when_missing=False,
        ))
    return records


def _existence_guard(script: Script, link: Link) -> int | None:
    """The line of a -e test of the BIOS-side path the link waits for, if any."""
    last = max(link.lines)
    tests = [
        number
        for number, line in script.code()
        if number < last
        and re.search(
            r"\[ -e \S*" + re.escape(link.bios_side) + "/", script.expand(line, number, set())
        )
    ]
    return tests[-1] if tests and last - tests[-1] <= 3 else None


EXTRACTORS: tuple[Callable[[RepoTree], list[Launcher]], ...] = (
    retroarch,
    amiberry,
    hatari,
    melonds,
    dsperate,
    nanoboyadvance,
    xemu,
    mednafen,
    yabasanshiro,
    duckstation,
    armsx2,
    pico8,
    patched_directories,
    links,
)


def extract_launchers(tree: RepoTree) -> list[dict]:
    """Every launcher record the extractors find, in extractor order."""
    return [record.entry() for extractor in EXTRACTORS for record in extractor(tree)]
