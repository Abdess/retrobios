"""The configs ROCKNIX installs per device, and the records of the BIOS paths they hold."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from typing import TypeVar

from .configgen_launchers import Launcher
from .shell_launchers import (
    FixedPaths,
    LauncherPatternMissing,
    RepoTree,
    Script,
    apply_evidence,
    config_placement,
    describe_keys,
    first_boot_placement,
    fixed_paths,
    settings,
    source_ref,
)


ROCKNIX = "projects/ROCKNIX"
DEVICES = f"{ROCKNIX}/devices"
STANDALONE = f"{ROCKNIX}/packages/emulators/standalone"
RETROARCH = f"{ROCKNIX}/packages/emulators/libretro/retroarch"
BIOS_ROOT = "/storage/roms/bios"
CONFIG_ROOT = "/storage/.config"
# The first-boot step copying every package's /usr/config to /storage/.config.
USERCONFIG = f"{ROCKNIX}/packages/sysutils/systemd/scripts/userconfig-setup"

Lines = list[tuple[str, set[int]]]
# What per_device groups configs by: equal values make one group.
Found = TypeVar("Found", bound=Hashable)


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
        for case_arm in re.finditer(r"^\s*([\w*|]+)\)(.*?);;", body, re.M | re.S):
            chosen = re.search(
                rf'CONFIG="([^"]+)"|\$\{{PKG_DIR\}}/{folder}/([^/\s]+)', case_arm.group(2)
            )
            if chosen:
                arms.append((case_arm.group(1).split("|"), chosen.group(1) or chosen.group(2)))
                mk_lines.add(mk.text.count("\n", 0, offset + case_arm.start(2)) + 1)
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
    read: Callable[[str, str], tuple[Found, set[int]]],
) -> list[tuple[str | None, Found, Lines]]:
    """Configs grouped by what read() finds in them.

    read(path, text) returns a comparable value and the lines it comes from.
    One group gives one result without a device. Otherwise each group names
    its devices, in the order of the devices directory.
    """
    groups: dict[Found, tuple[list[str], Lines]] = {}
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


def with_evidence(
    tree: RepoTree,
    record: Launcher,
    target: str,
    keys: list[str],
    start: Script | None = None,
    writers: tuple[str, ...] = (),
    source_name: str = "",
) -> Launcher:
    """A config record with the steps that put its file at ``target``.

    The first boot copies /usr/config to /storage/.config, leaving a file
    already there. A start script can copy or generate it again, and its
    sed lines rewriting one of the record's keys are the overrides.
    """
    placements = [first_boot_placement(Script(USERCONFIG, tree.read(USERCONFIG)), target)]
    if start is not None:
        placements.append(config_placement(
            start, target, keys, writers, source_name, required=False
        ))
    return apply_evidence(record, placements)


def _keys(value: FixedPaths) -> list[str]:
    return [f"[{section}] {key}" if section else key for section, key in value.keys]


@dataclass(frozen=True)
class Installed:
    """Where the launch puts a per-device config, and the start script doing it."""

    target: str = ""
    start: Script | None = None


def config_records(
    tree: RepoTree,
    emulator: str,
    package: str,
    file: str,
    passes_to_suffix: str = "",
    depends_on_option: str | None = None,
    installed: Installed | None = None,
    unread: Callable[[tuple[str, str]], bool] = lambda key: False,
) -> list[Launcher]:
    """fixed_name records for the bios paths of a config installed per device.

    ``unread`` drops the keys the shipped configs leave the emulator
    reading no file from.
    """
    installed = installed or Installed()
    configs = device_configs(tree, package, file)
    keys = [k for k in bios_keys(tree, [c.path for c in configs]) if not unread(k)]
    name = posixpath.basename(file)

    def read(path: str, text: str) -> tuple[FixedPaths, set[int]]:
        return fixed_paths(settings(text), keys, path)

    records = []
    for device, value, refs in per_device(tree, configs, f"{package}/package.mk", read):
        assert isinstance(value, FixedPaths)
        described = describe_keys(name, value.keys)
        records.append(with_evidence(
            tree,
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
            ),
            installed.target or f"{CONFIG_ROOT}/{posixpath.basename(package)}/{name}",
            _keys(value),
            installed.start,
        ))
    return records


def directory_records(
    tree: RepoTree,
    emulator: str,
    package: str,
    file: str,
    folder_key: tuple[str, str],
    file_keys: tuple[tuple[str, str], ...],
    target: str = "",
    start: str = "",
) -> list[Launcher]:
    """scans_dir records: the config hands a directory and leaves the file keys empty."""
    configs = device_configs(tree, package, file)
    name = posixpath.basename(file)

    def read(path: str, text: str) -> tuple[str, set[int]]:
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
        records.append(with_evidence(
            tree,
            Launcher(
                emulator=emulator,
                build="standalone",
                kind="scans_dir",
                names=[],
                source_ref=source_ref(refs),
                search_dir=folder,
                passes_to=passes,
                device=device,
            ),
            target,
            [f"[{s}] {k}" for s, k in (folder_key, *file_keys)],
            Script(start, tree.read(start)) if start else None,
        ))
    return records
