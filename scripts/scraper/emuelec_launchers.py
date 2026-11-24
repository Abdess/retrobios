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

from .configgen_launchers import Launcher
from scraper.shell_launchers import (
    describe_keys,
    fixed_paths,
    LauncherPatternMissing,
    Link,
    link_record,
    RepoTree,
    Script,
    settings,
    source_ref,
    words,
)
from .emuelec_runs import (
    BIN,
    BIOS_ROOT,
    EMULATORS,
    LIBRETRO,
    RETROARCH_MK,
    ROMS_ROOT,
    RUN_EMU,
    Runs,
    SX05RE,
    UTILS,
    ADVMAME_INSTALL,
    evidence,
    read,
    under,
)


def retroarch(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """system_directory, written by sed into the retroarch.cfg the package installs."""
    mk = read(tree, RETROARCH_MK)
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
    started = read(tree, path)
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
    script = read(tree, path)
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
        script = read(tree, path)
        found = script.links(BIOS_ROOT)
        if not found:
            raise script.missing(f"ln -s of a path under {BIOS_ROOT}")
        name = posixpath.basename(path)
        for link in found:
            record = link_record(runs.emulator(name), script, link, guard_lines=_link_guard(script, link))
            record.source_ref = f"{source_ref([runs.ref(name)])}, {record.source_ref}"
            records.append(record)
    for package in LINK_PACKAGES:
        script = read(tree, f"{package}/package.mk")
        found = script.links(BIOS_ROOT, fixed={"INSTALL": ""})
        if not found:
            raise script.missing(f"ln -s of a path under {BIOS_ROOT}")
        records.extend(
            link_record(posixpath.basename(package), script, link) for link in found
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
    mk = read(tree, f"{package}/package.mk")
    mk_line, _ = mk.find(r"cp -rf \$\{PKG_DIR\}/config/\* ", "config install")
    script = read(tree, f"{package}/scripts/duckstation.sh")
    run_line, _ = script.find(r'-settings "\$\{CONFIG_DIR\}/settings\.ini"', "-settings")
    name = posixpath.basename(script.path)
    lines = {found[k].line for k in (folder_key, *file_keys) if k in found}
    unset = describe_keys("", file_keys).strip()
    return [evidence(
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
        ),
        script,
        script.expand("${CONFIG_DIR}/settings.ini", run_line, set()),
        [f"[{s}] {k}" for s, k in (folder_key, *file_keys)],
        tree=tree,
        installed=[(mk.path, {mk_line})],
    )]


YABASANSHIRO_SCRIPTS = (
    f"{EMULATORS}/yabasanshiroSA_1_11/scripts/yabasanshiro.sh",
    f"{EMULATORS}/yabasanshiroSA_1_5/scripts/yabasanshiro1_5.sh",
)


def yabasanshiro(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The BIOS flag, set when the HLE option is off and the file exists."""
    records = []
    for path in YABASANSHIRO_SCRIPTS:
        script = read(tree, path)
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
    script = read(tree, path)
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
    script = read(tree, path)
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
    script = read(tree, f"{package}/scripts/hatari.start")
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
        if under(s.value) and "." in posixpath.basename(s.value)
    ]
    if not keys:
        raise LauncherPatternMissing(path, f"key naming a file under {BIOS_ROOT}")
    value, lines = fixed_paths(found, keys, path)
    mk = read(tree, f"{package}/package.mk")
    mk_line, _ = mk.find(r"cp -R \$\{PKG_DIR\}/config/\* ", "config install")
    name = posixpath.basename(script.path)
    return [evidence(
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
        ),
        script,
        script.expand("${" + copy.group(2) + "}", copy_line, set()),
        [f"[{s}] {k}" if s else k for s, k in value.keys],
        source_name=copy.group(1),
    )]


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
    mk = read(tree, f"{package}/package.mk")
    installs = [
        (number, found.group(1))
        for number, line in mk.code()
        if (found := ADVMAME_INSTALL.search(line))
    ]
    if not installs:
        raise mk.missing("advmame.rc install")
    by_value: dict[tuple[tuple[str, str], ...], list[tuple[str, set[int], int]]] = {}
    for mk_line, file in installs:
        path = f"{package}/config/{file}"
        keys = [s for s in settings(tree.read(path), separator=" ") if under(s.value, ROMS_ROOT)]
        if not any(under(s.value) for s in keys):
            raise LauncherPatternMissing(path, f"key naming a folder under {BIOS_ROOT}")
        value = tuple((s.key, s.value) for s in keys)
        by_value.setdefault(value, []).append((path, {s.line for s in keys}, mk_line))
    if len(by_value) != 1:
        raise mk.missing("one set of BIOS folders for every device")
    ((value, configs),) = by_value.items()
    script = read(tree, f"{package}/bin/advmame.sh")
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

    target = script.expand("${CONFIG_DIR}/advmame.rc", run_line, set())

    def proved(record: Launcher, key: str) -> Launcher:
        return evidence(record, script, target, [key], rewrites={sed_line}, tree=tree,
                         installed=[(mk.path, {mk_line for _, _, mk_line in configs})])

    records = []
    for key, folder in value:
        rewritten = folder.replace(sed.group(1), sed.group(2))
        if rewritten != folder:
            # Every system but the one the script rewrites the key for, and
            # that system with the rewritten folder.
            records.append(proved(Launcher(
                emulator=runs.emulator(name), build="standalone", kind="passes_path", names=[],
                source_ref=refs(test_line, sed_line), search_dir=folder,
                passes_to=f"advmame.rc {key}",
                depends_on_option=f"system != {test.group(1)}",
            ), key))
            records.append(proved(Launcher(
                emulator=runs.emulator(name), build="standalone", kind="passes_path", names=[],
                source_ref=refs(test_line, sed_line), search_dir=rewritten,
                passes_to=f"advmame.rc {key}", systems=[test.group(1)],
            ), key))
            continue
        records.append(proved(Launcher(
            emulator=runs.emulator(name), build="standalone", kind="passes_path", names=[],
            source_ref=refs(), search_dir=folder, passes_to=f"advmame.rc {key}",
        ), key))
    return records


def mame(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """The files mame.sh copies into bios/mame, and the folders mame.ini hands the core."""
    package = f"{LIBRETRO}/mame"
    script = read(tree, f"{package}/scripts/mame.sh")
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
        if not under(copy.group(3)):
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
    # mame.ini hands the core no folder: MAME.opt turns on
    # mame_mame_paths_enable, so the core passes no path option
    # (libretro mame src/osd/libretro/libretro-internal/retro_init.cpp:554-555),
    # and the ini MAME would read sits under a working directory no launcher
    # sets (src/emu/emuopts.cpp:49). Only the copies are the launcher's.
    return records


def scummvm(tree: RepoTree, runs: Runs) -> list[Launcher]:
    """--extrapath for the standalone build, and the scummvm.ini copied for the core."""
    path = f"{EMULATORS}/scummvmsa/bin/scummvm.start"
    script = read(tree, path)
    name = posixpath.basename(path)
    test_line, test = script.find(r'^\s*if \[ -d "([^"]+)" \]; then\s*$', "extra folder test")
    set_line, set_ = script.find(r'^\s*(\w+)="(--[\w-]+)=([^"]+)"', "extra path", test_line)
    run_line, run = script.find(rf"^\s*(\S+) .*\${set_.group(1)}\b", "start with it", set_line)
    core_line, core = script.find(r"-L /tmp/cores/(\w+)_libretro\.so", "libretro start")
    arm_line, arm = script.find(r'^\s*"(\w+)"\)', "setup arm", core_line)
    copy_line, copy = script.find(r"^\s*cp (\S+) (\S+)$", "copy into the BIOS folder", arm_line)
    launched = sorted({
        m.group(1) for _, line in runs.script.code()
        if (m := re.search(rf"\b{re.escape(name)} (\w+)", line))
    })
    if not launched:
        raise runs.script.missing(f"start of {name} with an action")
    action = f"{name} {arm.group(1)}"
    if arm.group(1) not in launched:
        # The copy runs from the setup action, never from a launch.
        action += f", an action no launch runs ({RUN_EMU.rsplit('/', 1)[-1]} passes {', '.join(launched)})"
    used = {copy_line}
    source = script.expand(copy.group(1), copy_line, used)
    target = script.expand(copy.group(2), copy_line, used)
    if not under(target):
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
            depends_on_option=action,
        ),
    ]


def dolphin(tree: RepoTree, runs: Runs) -> list[Launcher]:
    path = f"{EMULATORS}/dolphinSA/scripts/dolphin.sh"
    script = read(tree, path)
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
    utils = read(tree, UTILS)
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
        is_file = "." in posixpath.basename(value) and under(value)
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
