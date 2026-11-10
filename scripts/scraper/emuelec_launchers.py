"""EmuELEC's launcher layer, read from its packages at the pinned tag.

emuelecRunEmu.sh starts every game. A libretro core runs in RetroArch (or
retrorun) with /storage/roms/bios as its system directory. A standalone
emulator runs from the script the `case ${PLATFORM}` arm names for the core
ES passes (`"${EMU}" = "flycastsa"`), and that script links, moves, copies
or passes the file. Some packages ship the config the emulator reads
(duckstation, hatari, advancemame, mame), others link a BIOS folder at
install time (amiberry, timidity). The emulator of each record is the core
name the dispatch tests, or the package that installs the link.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .configgen_launchers import Launcher
from .rocknix_launchers import fixed_paths
from .shell_launchers import (
    LauncherPatternMissing,
    Link,
    RepoTree,
    Script,
    describe_keys,
    settings,
    source_ref,
    words,
)

SX05RE = "packages/sx05re"
BIN = f"{SX05RE}/emuelec/bin"
RUN_EMU = f"{BIN}/emuelecRunEmu.sh"
UTILS = f"{BIN}/emuelec-utils"
EMULATORS = f"{SX05RE}/emulators"
LIBRETRO = f"{SX05RE}/libretro"
RETROARCH_MK = f"{SX05RE}/libretro_base/retroarch/package.mk"
BIOS_ROOT = "/storage/roms/bios"
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
            if name is None or (emu is None and arm is None):
                continue
            names, at = ([emu[0]], emu[1]) if emu else arm  # type: ignore[misc]
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
        return ", ".join(self.of(name).emulators)

    def ref(self, name: str) -> tuple[str, set[int]]:
        return (RUN_EMU, set(self.of(name).lines))


def _read(tree: RepoTree, path: str) -> Script:
    return Script(path, tree.read(path))


def _under(path: str, root: str = BIOS_ROOT) -> bool:
    return path.rstrip("/") == root or path.startswith(root + "/")


def retroarch(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """system_directory, written by sed into the retroarch.cfg the package installs."""
    mk = _read(tree, RETROARCH_MK)
    sed_line, sed = mk.find(
        r"s/# system_directory =/system_directory =((?:\\/|[^/])+)/", "system_directory sed"
    )
    run_line, _ = runs.script.find(
        r"RUNTHIS='\$\{RABIN\}.* -L /tmp/cores/\$\{EMU\}\.so --config \$\{RACONF\}",
        "RetroArch start with --config",
    )
    return [
        Launcher(
            emulator="retroarch",
            build="libretro",
            kind="passes_path",
            names=[],
            source_ref=source_ref([(mk.path, {sed_line}), (RUN_EMU, {run_line})]),
            search_dir=sed.group(1).replace("\\/", "/"),
            passes_to="retroarch.cfg system_directory (--config)",
        )
    ]


def retrorun(tree: RepoTree, runs: Runs) -> list[Launcher]:
    script = runs.script
    base_line, base = script.find(r'^\s*RUNTHIS="(\w+)"\s*$', "retrorun command")
    test_line, _ = script.find(
        rf'if \[\[ "\$\{{EMULATOR\}}" = "{base.group(1)}" \]\]', f"{base.group(1)} test"
    )
    run_line, run = script.find(r"RUNTHIS\+=.*\s(-d)\s+(\S+)\s", "retrorun -d", base_line)
    return [
        Launcher(
            emulator=base.group(1),
            build="libretro",
            kind="passes_path",
            names=[],
            source_ref=source_ref([(RUN_EMU, {test_line, base_line, run_line})]),
            search_dir=run.group(2),
            passes_to=f"{base.group(1)} {run.group(1)}",
        )
    ]


def freej2me(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """JAVA_HOME set for the core, and the jar its script copies beside the JDK."""
    script = runs.script
    test_line, test = script.find(r'if \[ \$\{EMU\} == "(\w+)_libretro" \]', "core test")
    call_line, call = script.find(r"^\s*(\S+\.sh)\s*$", "script call", test_line)
    java_line, java = script.find(r"^\s*(JAVA_HOME)='([^']+)'", "JAVA_HOME", test_line)
    export_line, _ = script.find(rf"^\s*export {java.group(1)}\s*$", "export", java_line)
    core = test.group(1)
    path = f"{LIBRETRO}/{core}/scripts/{call.group(1)}"
    started = _read(tree, path)
    guard_line, guard = started.find(r'if \[\[ -f "([^"]+)" \]\]; then$', "JDK version test")
    copy_line, copy = started.find(r"^\s*cp -rf (\S+) (\S+)$", "jar copy", guard_line)
    source = copy.group(1)
    return [
        Launcher(
            emulator=core,
            build="libretro",
            kind="passes_path",
            names=[],
            source_ref=source_ref(
                [(RUN_EMU, {test_line, call_line, java_line, export_line}), (path, {guard_line})]
            ),
            search_dir=java.group(2),
            passes_to=f"environment {java.group(1)}",
        ),
        Launcher(
            emulator=core,
            build="libretro",
            kind="copies",
            names=[posixpath.basename(source)],
            source_ref=source_ref(
                [(RUN_EMU, {test_line, call_line}), (path, {guard_line, copy_line})]
            ),
            search_dir=posixpath.dirname(source),
            passes_to=copy.group(2),
            depends_on_option=f"{guard.group(1)} exists",
        ),
    ]


def pico8(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The folder the user drops in bios/ is moved where the binary runs from."""
    path = f"{BIN}/pico8.sh"
    script = _read(tree, path)
    guard_line, guard = script.find(r'if \[\[ -e "([^"]+)" \]\]; then$', "new version test")
    folder = guard.group(1)
    copy_line, copy = script.find(
        rf"^\s*cp -rf {re.escape(folder)}/\* (\S+)$", "copy of the folder", guard_line
    )
    target = copy.group(1)
    remove_line, _ = script.find(rf"^\s*rm -rf {re.escape(folder)}$", "removal", copy_line)
    mode_line, mode = script.find(
        rf"^\s*chmod \+x {re.escape(target)}/([^/\s]+)$", "executable bit", remove_line
    )
    binary = mode.group(1)
    starts = {
        n for n, line in script.code() if re.match(rf"\s*{re.escape(target)}/{binary} -", line)
    }
    if not starts:
        raise script.missing(f"start of {target}/{binary}")
    name = posixpath.basename(path)
    return [
        Launcher(
            emulator=runs.emulator(name),
            build="standalone",
            kind="moves",
            names=[binary],
            source_ref=source_ref(
                [runs.ref(name), (path, {guard_line, copy_line, remove_line, mode_line, *starts})]
            ),
            case_insensitive=False,
            search_dir=folder,
            passes_to=target,
            fails_when_missing=False,
            depends_on_option=f"{folder} exists",
        )
    ]


def link_record(emulator: str, script: Script, link: Link, extra: set[int]) -> Launcher:
    return Launcher(
        emulator=emulator,
        build="standalone",
        kind="links",
        names=list(link.names),
        source_ref=source_ref([(script.path, link.lines | extra)]),
        expands=link.expands or None,
        search_dir=link.bios_side,
        passes_to=f"symlink {link.link} -> {link.target}",
        fails_when_missing=False,
    )


def _link_guard(script: Script, link: Link) -> set[int]:
    """The `[ ! -L <link> ]` test the link waits for, when it is the one just above."""
    first = max(link.lines)
    tests = [
        number
        for number, line in script.code()
        if number < first
        and re.search(r"\[ ! -L ", line)
        and link.link in script.expand(line, number, set())
    ]
    return {tests[-1]} if tests and first - tests[-1] <= 4 else set()


# Start scripts whose ln -s commands put a BIOS folder where the emulator reads.
LINK_SCRIPTS = (
    f"{EMULATORS}/flycastsa/scripts/flycast.sh",
    f"{EMULATORS}/flycast-dojo/scripts/flycastdojo.sh",
)

# Packages whose package.mk links a BIOS folder into the installed tree.
LINK_PACKAGES = (
    f"{EMULATORS}/amiberry",
    f"{EMULATORS}/amiberry-lite",
    f"{SX05RE}/tools/sound/timidity",
)


def links(tree: RepoTree, runs: Runs) -> list[Launcher]:
    records = []
    for path in LINK_SCRIPTS:
        script = _read(tree, path)
        found = script.links(BIOS_ROOT)
        if not found:
            raise script.missing(f"ln -s of a path under {BIOS_ROOT}")
        name = posixpath.basename(path)
        for link in found:
            record = link_record(runs.emulator(name), script, link, _link_guard(script, link))
            record.source_ref = f"{source_ref([runs.ref(name)])}, {record.source_ref}"
            records.append(record)
    for package in LINK_PACKAGES:
        script = _read(tree, f"{package}/package.mk")
        found = script.links(BIOS_ROOT, fixed={"INSTALL": ""})
        if not found:
            raise script.missing(f"ln -s of a path under {BIOS_ROOT}")
        records.extend(
            link_record(posixpath.basename(package), script, link, set()) for link in found
        )
    return records


def duckstation(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The settings.ini the package ships hands a directory and leaves the paths empty."""
    package = f"{EMULATORS}/duckstation"
    path = f"{package}/config/settings.ini"
    found = {(s.section, s.key): s for s in settings(tree.read(path))}
    folder_key = ("BIOS", "SearchDirectory")
    file_keys = (("BIOS", "PathNTSCU"), ("BIOS", "PathNTSCJ"), ("BIOS", "PathPAL"))
    if folder_key not in found:
        raise LauncherPatternMissing(path, "[BIOS] SearchDirectory")
    set_files = [k for k in file_keys if k in found and found[k].value]
    if set_files:
        raise LauncherPatternMissing(path, f"empty [BIOS] {set_files[0][1]}")
    mk = _read(tree, f"{package}/package.mk")
    mk_line, _ = mk.find(r"cp -rf \$\{PKG_DIR\}/config/\* ", "config install")
    script = _read(tree, f"{package}/scripts/duckstation.sh")
    run_line, _ = script.find(r'-settings "\$\{CONFIG_DIR\}/settings\.ini"', "-settings")
    name = posixpath.basename(script.path)
    lines = {found[k].line for k in (folder_key, *file_keys) if k in found}
    unset = describe_keys("", file_keys).strip()
    return [
        Launcher(
            emulator=runs.emulator(name),
            build="standalone",
            kind="scans_dir",
            names=[],
            source_ref=source_ref(
                [runs.ref(name), (path, lines), (mk.path, {mk_line}), (script.path, {run_line})]
            ),
            search_dir=found[folder_key].value,
            passes_to=f"settings.ini [BIOS] SearchDirectory (-settings), {unset} unset",
        )
    ]


YABASANSHIRO_SCRIPTS = (
    f"{EMULATORS}/yabasanshiroSA_1_11/scripts/yabasanshiro.sh",
    f"{EMULATORS}/yabasanshiroSA_1_5/scripts/yabasanshiro1_5.sh",
)


def yabasanshiro(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The BIOS flag, set when the HLE option is off and the file exists."""
    records = []
    for path in YABASANSHIRO_SCRIPTS:
        script = _read(tree, path)
        option_line, option = script.find(r"^\s*(\w+)=\$\(get_ee_setting (\w+) ", "HLE option")
        test_line, test = script.find(
            rf'if \[ "\$\{{{option.group(1)}\}}" != (\w+) \]', "HLE option test", option_line
        )
        exists_line, exists = script.find(r'if \[ -e "([^"]+)" \]', "BIOS test", test_line)
        bios = exists.group(1)
        flag_line, flag = script.find(
            rf'^\s*(\w+)="(-\w) {re.escape(bios)}"$', "BIOS flag", exists_line
        )
        run_line, run = script.find(
            rf"\{{\s*(\S+) .*\$\{{{flag.group(1)}\}}", "start with the flag", flag_line
        )
        name = posixpath.basename(path)
        records.append(
            Launcher(
                emulator=runs.emulator(name),
                build="standalone",
                kind="fixed_name",
                names=[posixpath.basename(bios)],
                source_ref=source_ref(
                    [
                        runs.ref(name),
                        (path, {option_line, test_line, exists_line, flag_line, run_line}),
                    ]
                ),
                case_insensitive=False,
                search_dir=posixpath.dirname(bios),
                passes_to=f"{run.group(1)} {flag.group(2)}",
                fails_when_missing=False,
                depends_on_option=f"{option.group(2)} != {test.group(1)}",
            )
        )
    return records


def jzintv(tree: RepoTree, runs: Runs) -> list[Launcher]:
    path = f"{EMULATORS}/jzintv/scripts/jzintv.sh"
    script = _read(tree, path)
    run_line, run = script.find(r"^\s*exec (\S+) .*\s(-p)\s+(\S+)\s", "start with -p")
    name = posixpath.basename(path)
    return [
        Launcher(
            emulator=runs.emulator(name),
            build="standalone",
            kind="passes_path",
            names=[],
            source_ref=source_ref([runs.ref(name), (path, {run_line})]),
            search_dir=run.group(3).rstrip("/"),
            passes_to=f"{run.group(1)} {run.group(2)}",
        )
    ]


def mupen64plus(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The 64DD IPL names, tried in order, passed only beside a .ndd disk."""
    path = f"{EMULATORS}/mupen64plussa/mupen64plussa-core/m64p.sh"
    script = _read(tree, path)
    fallbacks = [
        (number, found)
        for number, line in script.code()
        if (found := re.search(r'\[ ! -f "\$\{(\w+)\}" \] && \1="([^"]+)"', line))
    ]
    if not fallbacks:
        raise script.missing("fallback name test")
    var = fallbacks[0][1].group(1)
    first = script.value(var, fallbacks[0][0])
    if first is None:
        raise script.missing(f"assignment of {var}")
    used = {first.line, *(n for n, _ in fallbacks)}
    paths = [
        script.expand(v, n, used)
        for n, v in [(first.line, first.value), *((n, f.group(2)) for n, f in fallbacks)]
    ]
    folders = {posixpath.dirname(p) for p in paths}
    if len(folders) != 1:
        raise script.missing(f"one folder for the {var} names")
    test_line, test = script.find(
        rf'if \[ -f "([^"]+)" \] && \[ -f "\$\{{{var}\}}" \]', "disk and IPL test"
    )
    passes = [
        (number, found)
        for number, line in script.code()
        if (found := re.search(rf'^\s*(\S+) .*(--[\w-]+) "\$\{{{var}\}}"', line))
    ]
    if not passes:
        raise script.missing(f"flag that hands {var}")
    flags = sorted({f"{f.group(1)} {f.group(2)}" for _, f in passes})
    name = posixpath.basename(path)
    return [
        Launcher(
            emulator=runs.emulator(name),
            build="standalone",
            kind="names_searched",
            names=[posixpath.basename(p) for p in paths],
            source_ref=source_ref(
                [runs.ref(name), (path, used | {test_line} | {n for n, _ in passes})]
            ),
            case_insensitive=False,
            search_dir=folders.pop(),
            passes_to=", ".join(flags),
            fails_when_missing=False,
            depends_on_option=f'-f "{test.group(1)}"',
        )
    ]


def hatari(tree: RepoTree, runs: Runs) -> list[Launcher]:
    package = f"{EMULATORS}/hatarisa"
    script = _read(tree, f"{package}/scripts/hatari.start")
    copy_line, copy = script.find(r'^\s*cp \S+/([\w.-]+\.cfg) "\$(\w+)"', "default config copy")
    run_lines = {
        n
        for n, line in script.code()
        if n > copy_line and f'--configfile "${copy.group(2)}"' in line
    }
    if not run_lines:
        raise script.missing(f"--configfile ${copy.group(2)}")
    path = f"{package}/config/conf/{copy.group(1)}"
    found = settings(tree.read(path))
    keys = [
        (s.section, s.key)
        for s in found
        if _under(s.value) and "." in posixpath.basename(s.value)
    ]
    if not keys:
        raise LauncherPatternMissing(path, f"key naming a file under {BIOS_ROOT}")
    value, lines = fixed_paths(found, keys, path)
    mk = _read(tree, f"{package}/package.mk")
    mk_line, _ = mk.find(r"cp -R \$\{PKG_DIR\}/config/\* ", "config install")
    name = posixpath.basename(script.path)
    return [
        Launcher(
            emulator=runs.emulator(name),
            build="standalone",
            kind="fixed_name",
            names=list(value.names),
            source_ref=source_ref(
                [runs.ref(name), (path, lines), (mk.path, {mk_line}),
                 (script.path, {copy_line, *run_lines})]
            ),
            search_dir=value.search_dir,
            passes_to=f"{describe_keys(copy.group(1), value.keys)} (--configfile)",
        )
    ]


_ADVMAME_SYSTEM = re.compile(r'^\s*if \[\[ "\$\{1\}" = "([\w-]+)" \]\]; then$')
_ADVMAME_SED = re.compile(r'^\s*sed -i "s\|([^|]+)\|([^|]+)\|g" \$\{CONFIG_DIR\}/advmame\.rc$')


def advancemame(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """Folder keys of the advmame.rc package.mk installs, one per device branch.

    A key under the roms root is one too: dir_rom is /storage/roms/mame. The
    start script rewrites the config for the system it is launched for
    (advmame.sh:26-30): /roms/mame becomes /roms/arcade for arcade, so that
    system reads its own record.
    """
    package = f"{EMULATORS}/advancemame"
    mk = _read(tree, f"{package}/package.mk")
    installs = [
        (number, found.group(1))
        for number, line in mk.code()
        if (found := _ADVMAME_INSTALL.search(line))
    ]
    if not installs:
        raise mk.missing("advmame.rc install")
    by_value: dict[tuple[tuple[str, str], ...], list[tuple[str, set[int], int]]] = {}
    for mk_line, file in installs:
        path = f"{package}/config/{file}"
        keys = [s for s in settings(tree.read(path), separator=" ") if _under(s.value, ROMS_ROOT)]
        if not any(_under(s.value) for s in keys):
            raise LauncherPatternMissing(path, f"key naming a folder under {BIOS_ROOT}")
        value = tuple((s.key, s.value) for s in keys)
        by_value.setdefault(value, []).append((path, {s.line for s in keys}, mk_line))
    if len(by_value) != 1:
        raise mk.missing("one set of BIOS folders for every device")
    ((value, configs),) = by_value.items()
    script = _read(tree, f"{package}/bin/advmame.sh")
    run_line, _ = script.find(r"^\s*(?:\w+=\S+ )*advmame ", "advmame start")
    test_line, test = script.find(_ADVMAME_SYSTEM.pattern, "system test", end=run_line)
    sed_line, sed = script.find(_ADVMAME_SED.pattern, "system rewrite", test_line + 1, test_line + 1)
    name = posixpath.basename(script.path)

    def refs(*lines: int) -> str:
        return source_ref([
            runs.ref(name),
            *((path, lines) for path, lines, _ in configs),
            (mk.path, {mk_line for _, _, mk_line in configs}),
            (script.path, {run_line, *lines}),
        ])

    found = []
    for key, folder in value:
        rewritten = folder.replace(sed.group(1), sed.group(2))
        if rewritten != folder:
            # Every system but the one the script rewrites the key for, and
            # that system with the rewritten folder.
            found.append(Launcher(
                emulator=runs.emulator(name), build="standalone", kind="passes_path", names=[],
                source_ref=refs(test_line, sed_line), search_dir=folder,
                passes_to=f"advmame.rc {key}",
                depends_on_option=f"system != {test.group(1)}",
            ))
            found.append(Launcher(
                emulator=runs.emulator(name), build="standalone", kind="passes_path", names=[],
                source_ref=refs(test_line, sed_line), search_dir=rewritten,
                passes_to=f"advmame.rc {key}", systems=[test.group(1)],
            ))
            continue
        found.append(Launcher(
            emulator=runs.emulator(name), build="standalone", kind="passes_path", names=[],
            source_ref=refs(), search_dir=folder, passes_to=f"advmame.rc {key}",
        ))
    return found


def mame(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The files mame.sh copies into bios/mame, and the folders mame.ini hands the core."""
    package = f"{LIBRETRO}/mame"
    script = _read(tree, f"{package}/scripts/mame.sh")
    name = posixpath.basename(script.path)
    emulator = runs.emulator(name)
    records = []
    guard: tuple[int, str] | None = None
    for number, line in script.code():
        if found := re.search(r'if \[ ! -f "([^"]+)" \]', line):
            guard = (number, found.group(1))
            continue
        copy = re.match(r'\s*cp -rf "([^"]+)/"(\S+) "([^"]+)"\s*$', line)
        if copy is None:
            continue
        if guard is None:
            raise script.missing(f"test before the copy at line {number}")
        if not _under(copy.group(3)):
            continue
        records.append(
            Launcher(
                emulator=emulator,
                build="libretro",
                kind="copies",
                names=[copy.group(2)],
                source_ref=source_ref([runs.ref(name), (script.path, {guard[0], number})]),
                search_dir=copy.group(1),
                passes_to=copy.group(3),
                fails_when_missing=False,
                depends_on_option=f"{guard[1]} absent",
            )
        )
    if not records:
        raise script.missing(f"copy into {BIOS_ROOT}")
    ini = next((r for r in records if r.names == ["mame*"]), None)
    if ini is None:
        raise script.missing("copy of mame.ini")
    option_path = f"{package}/config/MAME/MAME.opt"
    option = next(
        (s for s in settings(tree.read(option_path)) if s.key == "mame_read_config"), None
    )
    if option is None:
        raise LauncherPatternMissing(option_path, "mame_read_config")
    ini_path = f"{package}/config/ini/mame.ini"
    # MAME reads from the folders its *path options name and writes to its
    # *_directory ones.
    folders = [
        (s, [p for p in s.value.split(";") if _under(p)])
        for s in settings(tree.read(ini_path), separator=" ")
        if s.key.endswith("path")
    ]
    folders = [(s, parts) for s, parts in folders if parts]
    if not folders:
        raise LauncherPatternMissing(ini_path, f"path under {BIOS_ROOT}")
    for setting, parts in folders:
        for part in parts:
            records.append(
                Launcher(
                    emulator=emulator,
                    build="libretro",
                    kind="passes_path",
                    names=[],
                    source_ref=source_ref(
                        [(ini_path, {setting.line}), (option_path, {option.line})]
                    ) + f", {ini.source_ref}",
                    search_dir=part.rstrip("/"),
                    passes_to=f"mame.ini {setting.key}",
                    depends_on_option=f"mame_read_config = {option.value}",
                )
            )
    return records


def scummvm(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """--extrapath for the standalone build, and the scummvm.ini copied for the core."""
    path = f"{EMULATORS}/scummvmsa/bin/scummvm.start"
    script = _read(tree, path)
    name = posixpath.basename(path)
    test_line, test = script.find(r'^\s*if \[ -d "([^"]+)" \]; then\s*$', "extra folder test")
    set_line, set_ = script.find(r'^\s*(\w+)="(--[\w-]+)=([^"]+)"', "extra path", test_line)
    run_line, run = script.find(rf"^\s*(\S+) .*\${set_.group(1)}\b", "start with it", set_line)
    core_line, core = script.find(r"-L /tmp/cores/(\w+)_libretro\.so", "libretro start")
    arm_line, arm = script.find(r'^\s*"(\w+)"\)', "setup arm", core_line)
    copy_line, copy = script.find(r"^\s*cp (\S+) (\S+)$", "copy into the BIOS folder", arm_line)
    used = {copy_line}
    source = script.expand(copy.group(1), copy_line, used)
    target = script.expand(copy.group(2), copy_line, used)
    if not _under(target):
        raise script.missing(f"copy into {BIOS_ROOT}")
    return [
        Launcher(
            emulator=runs.emulator(name),
            build="standalone",
            kind="passes_path",
            names=[],
            source_ref=source_ref([runs.ref(name), (path, {test_line, set_line, run_line})]),
            search_dir=set_.group(3),
            passes_to=f"{run.group(1)} {set_.group(2)}",
            depends_on_option=f"{test.group(1)} exists",
        ),
        Launcher(
            emulator=core.group(1),
            build="libretro",
            kind="copies",
            names=[posixpath.basename(source)],
            source_ref=source_ref([(path, {core_line, arm_line} | used)]),
            search_dir=posixpath.dirname(source),
            passes_to=target,
            fails_when_missing=False,
            depends_on_option=f"{name} {arm.group(1)}",
        ),
    ]


def dolphin(tree: RepoTree, runs: Runs) -> list[Launcher]:
    path = f"{EMULATORS}/dolphinSA/scripts/dolphin.sh"
    script = _read(tree, path)
    run_line, run = script.find(r"\b(XDG_DATA_HOME)=(\S+) .*\bdolphin-emu", "XDG_DATA_HOME start")
    name = posixpath.basename(path)
    return [
        Launcher(
            emulator=runs.emulator(name),
            build="standalone",
            kind="passes_path",
            names=[],
            source_ref=source_ref([runs.ref(name), (path, {run_line})]),
            search_dir=run.group(2),
            passes_to=f"environment {run.group(1)}",
        )
    ]


def midi(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The MIDI synth set_midi_source starts for the ra_midi_output setting."""
    script = runs.script
    setting_line, setting = script.find(
        r'^\s*(\w+)=\$\(get_ee_setting "(\w*midi\w*)" ', "MIDI setting"
    )
    call_line, _ = script.find(
        rf'set_midi_source "\$\{{{setting.group(1)}\}}"', "set_midi_source call", setting_line
    )
    utils = _read(tree, UTILS)
    head_line, _ = utils.find(r"^\s*function set_midi_source\(\)", "set_midi_source")
    end_line, _ = utils.find(r"^\s*esac\b", "end of the source case", head_line)
    records = []
    arm: tuple[int, str] | None = None
    for number, line in utils.code():
        if number <= head_line or number >= end_line:
            continue
        if found := re.match(r"\s*([\w-]+)\)\s*$", line):
            arm = (number, found.group(1))
            continue
        command = [w.text for w in words(line)]
        paths = [
            (command[i - 1], value)
            for i, value in enumerate(command)
            if i and command[i - 1].startswith("-") and re.search(r"(^|/)bios(/|$)", value)
        ]
        if not paths or arm is None:
            continue
        ((flag, value),) = paths
        is_file = "." in posixpath.basename(value) and _under(value)
        records.append(
            Launcher(
                emulator=command[0],
                build="standalone",
                kind="fixed_name" if is_file else "passes_path",
                names=[posixpath.relpath(value, BIOS_ROOT)] if is_file else [],
                source_ref=source_ref(
                    [(RUN_EMU, {setting_line, call_line}), (UTILS, {head_line, arm[0], number})]
                ),
                slot=arm[1],
                case_insensitive=False if is_file else None,
                search_dir=BIOS_ROOT if is_file else value.rstrip("/"),
                passes_to=f"{command[0]} {flag}",
                fails_when_missing=False,
                depends_on_option=f"{setting.group(2)} = {arm[1]}",
            )
        )
    if not records:
        raise utils.missing("MIDI synth started with a BIOS path")
    return records


EXTRACTORS: tuple[Callable[[RepoTree, Runs], list[Launcher]], ...] = (
    retroarch,
    retrorun,
    freej2me,
    mame,
    pico8,
    links,
    duckstation,
    yabasanshiro,
    jzintv,
    mupen64plus,
    hatari,
    advancemame,
    scummvm,
    dolphin,
    midi,
)


def extract_launchers(tree: RepoTree) -> list[dict]:
    """Every launcher record the extractors find, in extractor order."""
    runs = Runs(tree)
    return [record.entry() for extractor in EXTRACTORS for record in extractor(tree, runs)]
