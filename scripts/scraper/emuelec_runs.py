"""Which script emuelecRunEmu.sh starts for each core, and the lines that put a config in place."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .configgen_launchers import Launcher
from .shell_launchers import (
    RepoTree,
    Script,
    apply_evidence,
    config_placement,
    first_boot_placement,
    words,
)
from model.launcherrecords import join_emulators


SX05RE = "packages/sx05re"
BIN = f"{SX05RE}/emuelec/bin"
RUN_EMU = f"{BIN}/emuelecRunEmu.sh"
UTILS = f"{BIN}/emuelec-utils"
EMULATORS = f"{SX05RE}/emulators"
LIBRETRO = f"{SX05RE}/libretro"
RETROARCH_MK = f"{SX05RE}/libretro_base/retroarch/package.mk"
BIOS_ROOT = "/storage/roms/bios"
EMUELEC_MK = f"{SX05RE}/emuelec/package.mk"
# The copy of every package's /usr/config into /storage/.config at each boot,
# an existing file kept (cp -i answered by false).
USERCONFIG = "packages/sysutils/systemd/scripts/userconfig-setup"
# The roms root that holds it (packages/sx05re/libretro_base/retroarch/package.mk:112,117).
ROMS_ROOT = "/storage/roms"

_EMU_TEST = re.compile(r'\$\{?EMU\}?"?\s*==?\s*"([^"]+)"')
_ARM = re.compile(r'^\s*((?:"[^"]+"\|?)+)\)\s*$')
_RUNTHIS = re.compile(r"""^\s*RUNTHIS\+?=(['"])(.*)\1\s*$""")
_SCRIPT = re.compile(r"[\w./-]+\.(?:sh|start)$")
_ADVMAME_INSTALL = re.compile(r"cp -r \$\{PKG_DIR\}/config/(advmame\.rc\w*) \S+/advmame\.rc$")


@dataclass
class Dispatch:
    """The cores emuelecRunEmu.sh hands to one script, and the lines that do it."""

    emulators: list[str] = field(default_factory=list)
    lines: set[int] = field(default_factory=set)


class Runs:
    """emuelecRunEmu.sh, read once: which core starts which script."""

    def __init__(self, tree: RepoTree) -> None:
        self.script = Script(RUN_EMU, tree.read(RUN_EMU))
        self.by_script: dict[str, Dispatch] = {}
        emu: tuple[str, int] | None = None
        arm: tuple[list[str], int] | None = None
        for number, line in self.script.code():
            if found := _ARM.match(line):
                arm = ([p.strip('"') for p in found.group(1).split("|") if p], number)
                emu = None
                continue
            if re.match(r"\s*(;;|esac\b)", line):
                arm, emu = None, None
                continue
            if found := _EMU_TEST.search(line):
                emu = (found.group(1).removesuffix("_libretro"), number)
                continue
            if re.match(r"\s*fi\b", line):
                emu = None
                continue
            run = _RUNTHIS.match(line)
            command = words(run.group(2) if run else line)
            name = next(
                (posixpath.basename(w.text) for w in command if _SCRIPT.fullmatch(w.text)), None
            )
            if name is None:
                continue
            if emu is not None:
                names, at = [emu[0]], emu[1]
            elif arm is not None:
                names, at = arm
            else:
                continue
            entry = self.by_script.setdefault(name, Dispatch())
            entry.emulators.extend(n for n in names if n not in entry.emulators)
            entry.lines |= {at, number}
        if not self.by_script:
            raise self.script.missing("script started for a core")

    def of(self, name: str) -> Dispatch:
        if name not in self.by_script:
            raise self.script.missing(f"start of {name}")
        return self.by_script[name]

    def emulator(self, name: str) -> str:
        return join_emulators(self.of(name).emulators)

    def ref(self, name: str) -> tuple[str, set[int]]:
        return (RUN_EMU, set(self.of(name).lines))


def _storage_path(tree: RepoTree, target: str) -> str:
    """target with the /emuelec link resolved to the folder it points at.

    The emuelec package links /emuelec to /storage/.config/emuelec, where
    the first-boot copy of /usr/config lands.
    """
    mk = _read(tree, EMUELEC_MK)
    _line, link = mk.find(r"ln -sf (/storage/\S+) \$\{INSTALL\}(/emuelec)$", "/emuelec link")
    if target == link.group(2) or target.startswith(link.group(2) + "/"):
        return link.group(1) + target[len(link.group(2)):]
    return target


def _evidence(
    record: Launcher,
    script: Script,
    target: str,
    keys: list[str],
    source_name: str = "",
    rewrites: Iterable[int] = (),
    tree: RepoTree | None = None,
    installed: Iterable[tuple[str, Iterable[int]]] = (),
) -> Launcher:
    """A config record with the lines that put its file in place: the
    first-boot copy of /usr/config when ``tree`` is given, then the start
    script's own. ``installed`` are the package.mk lines putting the file
    in /usr/config.

    ``rewrites`` are lines the extractor read as rewriting the record's
    values without naming their keys (advmame.sh's sed of /roms/mame).
    """
    placements = []
    if tree is not None:
        placements.append(first_boot_placement(_read(tree, USERCONFIG), _storage_path(tree, target)))
    placement = config_placement(script, target, keys, source_name=source_name,
                                 required=not placements or not placements[0].install)
    placement.overrides |= set(rewrites)
    placements.append(placement)
    return apply_evidence(record, placements, installed)


def _read(tree: RepoTree, path: str) -> Script:
    return Script(path, tree.read(path))


def _under(path: str, root: str = BIOS_ROOT) -> bool:
    return path.rstrip("/") == root or path.startswith(root + "/")
