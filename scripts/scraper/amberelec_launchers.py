"""AmberELEC's launcher layer, read from runemu.py and its emulator scripts.

EmulationStation hands every launch to runemu.py. A libretro core runs in
RetroArch or retrorun with the system directory their configs name, MAME
machines get a .cmd file with a `-rp` search path, and every other emulator
runs the script its standalone_emulators table names (/usr/bin/<name>.sh,
installed from the package). Those scripts, and the configs their packages
install, say which file under /storage/roms/bios is opened: yabasanshiro.sh
tests saturn_bios.bin and passes it with -b, Hatari's default config names
tos.img.

runemu.py is read with ast, the scripts with shell_launchers' readers. An
extractor whose construct is gone raises instead of returning nothing.
"""

from __future__ import annotations

import ast
import posixpath
import re
from collections.abc import Callable
from typing import Any

try:
    from .configgen_launchers import Launcher, Source
    from .shell_launchers import (
        LauncherPatternMissing,
        Script,
        config_placement,
        describe_keys,
        evidence_fields,
        settings,
        source_ref,
    )
except ImportError:
    from configgen_launchers import Launcher, Source  # type: ignore[no-redef]
    from shell_launchers import (  # type: ignore[no-redef]
        LauncherPatternMissing,
        Script,
        config_placement,
        describe_keys,
        evidence_fields,
        settings,
        source_ref,
    )

BIOS = "/storage/roms/bios"
RUNEMU = "packages/amberelec/sources/scripts/runemu.py"
RETROARCH_CFG = "packages/games/tools/retroarch/sources/retroarch.cfg"
RETRORUN = "packages/games/tools/retrorun/retrorun.sh"
HATARI_CONFIG = "packages/games/emulators/hatarisa/config/conf/Atari-ST-default.cfg"
# The first-boot copy of every package's /usr/config into /storage/.config.
USERCONFIG = "packages/sysutils/systemd/scripts/userconfig-setup"
AMIBERRY_PACKAGE = "packages/games/emulators/amiberry/package.mk"
AMIBERRY_CONFIGS = "packages/games/emulators/amiberry/config/conf"
FREEJ2ME = (
    ("freej2me", "packages/games/libretro/freej2me/freej2me.sh"),
    ("freej2me-plus", "packages/games/libretro/freej2me-plus/freej2me-plus.sh"),
)
EASYRPG = "packages/games/libretro/easyrpg/easyrpg.sh"

# The script each standalone_emulators entry runs, as the package installs it
# to /usr/bin. scripts() checks each against runemu's table.
SCRIPTS = {
    "AMIBERRY": "packages/games/emulators/amiberry/scripts/amiberry.sh",
    "HATARISA": "packages/games/emulators/hatarisa/scripts/hatari.sh",
    "SCUMMVMSA": "packages/games/emulators/scummvmsa/scummvm.sh",
    "pico8": "packages/amberelec/sources/pico-8.sh",
    "piemu": "packages/games/emulators/piemu/bin/piemu.sh",
    "yabasanshiroSA": "packages/games/emulators/yabasanshiroSA/yabasanshiro.sh",
}

Read = Callable[[str], str]


class Runemu:
    """runemu.py, parsed: the standalone table and the RetroArch command."""

    def __init__(self, read: Read) -> None:
        self.src = Source(RUNEMU, read(RUNEMU))
        node = self.src.assignment("standalone_emulators")
        if not isinstance(node.value, ast.Dict):
            self.src.fail("standalone_emulators is not a dict display")
        self.table: dict[str, tuple[str, int]] = {}
        for key, value in zip(node.value.keys, node.value.values):
            if not (
                isinstance(key, ast.Constant)
                and isinstance(value, ast.Call)
                and len(value.args) >= 2
                and isinstance(value.args[1], ast.List)
            ):
                self.src.fail(f"entry at line {getattr(key, 'lineno', '?')} is not StandaloneEmulator(name, [args])")
            args = [a.value for a in value.args[1].elts if isinstance(a, ast.Constant)]
            script = next((a for a in args if str(a).endswith(".sh")), None)
            if script is None:
                self.src.fail(f"{ast.unparse(key)} runs no .sh script")
            self.table[str(key.value)] = (str(script), value.lineno)

    def script(self, emulator: str) -> tuple[str, int]:
        """The repository script runemu runs for emulator, and the table line."""
        if emulator not in self.table:
            self.src.fail(f"standalone_emulators has no {emulator}")
        installed, line = self.table[emulator]
        path = SCRIPTS[emulator]
        if posixpath.basename(installed) != posixpath.basename(path):
            self.src.fail(f"{emulator} runs {installed}, not {posixpath.basename(path)}")
        return path, line


def _evidence(
    read: Read, record: Launcher, target: str, keys: list[str],
    start: Script | None = None, source_name: str = "",
) -> Launcher:
    """A config record with the steps that put its file at ``target``: the
    first-boot copy of /usr/config, then the start script's own copy."""
    setup = Script(USERCONFIG, read(USERCONFIG))
    placements = [config_placement(setup, target, required=False, sources=("/usr/config/",))]
    if start is not None:
        placements.append(
            config_placement(start, target, keys, source_name=source_name, required=False)
        )
    fields = evidence_fields(placements)
    record.installs = fields["installs"]
    record.kept_if_present = fields["kept_if_present"]
    record.overrides = fields["overrides"]
    return record


def retroarch(read: Read) -> list[Launcher]:
    """system_directory of the retroarch.cfg the retroarch package installs."""
    found = [s for s in settings(read(RETROARCH_CFG)) if s.key == "system_directory"]
    if len(found) != 1:
        raise LauncherPatternMissing(RETROARCH_CFG, "one system_directory")
    return [_evidence(read, Launcher(
        emulator="retroarch", build="libretro", kind="passes_path", names=[],
        search_dir=found[0].value, passes_to="retroarch.cfg system_directory",
        fails_when_missing=False, source_ref=source_ref([(RETROARCH_CFG, [found[0].line])]),
    ), "/storage/.config/retroarch/retroarch.cfg", ["system_directory"])]


def retrorun(read: Read) -> list[Launcher]:
    """The -d directory retrorun.sh passes to retrorun."""
    script = Script(RETRORUN, read(RETRORUN))
    line, found = script.find(r"^\s*/usr/bin/retrorun\s.*\s-d\s+(\S+)", "retrorun -d")
    return [Launcher(
        emulator="retrorun", build="libretro", kind="passes_path", names=[],
        search_dir=found.group(1).strip('"'), passes_to="command line -d",
        fails_when_missing=False, source_ref=source_ref([(RETRORUN, [line])]),
    )]


def mame(runemu: Runemu) -> list[Launcher]:
    """The `-rp` search path of the .cmd file runemu writes for a MAME machine."""
    src = runemu.src
    commands = [
        node for node in ast.walk(src.function("get_retroarch_command"))
        if isinstance(node, ast.JoinedStr)
        and any(isinstance(p, ast.Constant) and " -rp " in str(p.value) for p in node.values)
    ]
    if not commands:
        src.fail("get_retroarch_command writes no -rp search path")
    paths = []
    for node in commands:
        text = "".join(str(p.value) for p in node.values if isinstance(p, ast.Constant))
        paths.append(text.split(" -rp ", 1)[1].split()[0])
    if len(set(paths)) != 1:
        src.fail(f"the MAME commands differ in their search path: {sorted(set(paths))}")
    guard = next(
        node for node in ast.walk(src.function("get_retroarch_command"))
        if isinstance(node, ast.If) and ast.unparse(node.test) == "self.emulator == 'mame'"
    )
    return [Launcher(
        emulator="mame", build="libretro", kind="passes_path", names=[],
        search_dir=paths[0], passes_to=".cmd -rp", fails_when_missing=False,
        depends_on_option=ast.unparse(guard.test),
        source_ref=src.ref([
            src.span(guard.test), *((n.lineno, n.end_lineno or n.lineno) for n in commands),
        ]),
    )]


def _bios_files(path: str, text: str) -> tuple[list[tuple[tuple[str, str], str]], set[int]]:
    """((section, key), name under BIOS) for each config key whose value is a BIOS file."""
    prefix = BIOS + "/"
    found = [s for s in settings(text) if s.value.startswith(prefix)]
    if not found:
        raise LauncherPatternMissing(path, f"key naming a file under {BIOS}")
    return [((s.section, s.key), s.value[len(prefix):]) for s in found], {s.line for s in found}


def hatari(read: Read, runemu: Runemu) -> list[Launcher]:
    """szTosImageFileName of the default config hatari.sh copies and passes."""
    path, table_line = runemu.script("HATARISA")
    script = Script(path, read(path))
    name = posixpath.basename(HATARI_CONFIG)
    copied, copy = script.find(
        rf"^\s*cp\s+\S*/{re.escape(name)}\s+\"?(\$\{{?\w+\}}?)", f"cp of {name}"
    )
    passed, _ = script.find(r"\shatari\s+--configfile\s", "hatari --configfile")
    files, lines = _bios_files(HATARI_CONFIG, read(HATARI_CONFIG))
    return [_evidence(read, Launcher(
        emulator="HATARISA", build="standalone", kind="fixed_name",
        names=[n for _k, n in files], case_insensitive=False, search_dir=BIOS,
        passes_to=describe_keys(name, tuple(k for k, _n in files)),
        fails_when_missing=False,
        source_ref=source_ref([
            (RUNEMU, [table_line]), (path, [copied, passed]), (HATARI_CONFIG, lines),
        ]),
    ), script.expand(copy.group(1), copied, set()),
        [f"[{s}] {k}" if s else k for (s, k), _n in files], script, name)]


def yabasanshiro(read: Read, runemu: Runemu) -> list[Launcher]:
    """`if [ -e <bios> ]; then BIOS="-b <bios>"`, skipped when HLE is chosen."""
    path, table_line = runemu.script("yabasanshiroSA")
    script = Script(path, read(path))
    tested, test = script.find(rf'if \[ -e "({re.escape(BIOS)}/[^"]+)" \]', "BIOS presence test")
    flag_line, flag = script.find(
        rf'BIOS="(-\w+) {re.escape(test.group(1))}"', "BIOS flag", tested
    )
    hle_line, hle = script.find(r'get_setting "(\w*hle\w*)"', "HLE setting")
    guard_line, _ = script.find(r'if \[ "\$\{HLEBIOS\}" != 1 \]', "HLE test")
    used_line, _ = script.find(r"\$\{BIOS\}", "BIOS on the command line", flag_line + 1)
    return [Launcher(
        emulator="yabasanshiroSA", build="standalone", kind="fixed_name",
        names=[test.group(1)[len(BIOS) + 1:]], case_insensitive=False, search_dir=BIOS,
        passes_to=f"command line {flag.group(1)}", fails_when_missing=False,
        depends_on_option=hle.group(1),
        source_ref=source_ref([
            (RUNEMU, [table_line]),
            (path, [hle_line, guard_line, tested, flag_line, used_line]),
        ]),
    )]


def pico8(read: Read, runemu: Runemu) -> list[Launcher]:
    """`if [ ! -f A ] || [ ! -f B ]; then text_viewer ...; else A ...`."""
    path, table_line = runemu.script("pico8")
    script = Script(path, read(path))
    line, test = script.find(r'if \[ ! -f "([^"]+)" \] \|\| \[ ! -f "([^"]+)" \]', "binary test")
    message_line, message = script.find(r'text_viewer .*-t "([^"]+)"', "missing message", line)
    binary = test.group(1)
    run_line, _ = script.find(rf"^\s*{re.escape(binary)}\s", f"{binary} run", message_line)
    folders = {posixpath.dirname(test.group(1)), posixpath.dirname(test.group(2))}
    if len(folders) != 1:
        raise script.missing("both binaries in one folder")
    return [Launcher(
        emulator="pico8", build="standalone", kind="fixed_name",
        names=[posixpath.basename(test.group(1)), posixpath.basename(test.group(2))],
        case_insensitive=False, search_dir=folders.pop(), passes_to="exec",
        fails_when_missing=message.group(1),
        source_ref=source_ref([(RUNEMU, [table_line]), (path, [line, message_line, run_line])]),
    )]


def piemu(read: Read, runemu: Runemu) -> list[Launcher]:
    """The BIOS file piemu.sh hands to mkpfi to build the flash image."""
    path, table_line = runemu.script("piemu")
    script = Script(path, read(path))
    names: list[str] = []
    lines: set[int] = set()
    for number, line in script.code():
        found = re.search(r'/usr/bin/mkpfi\s+"([^"]+)"', line)
        if found is None:
            continue
        used: set[int] = {number}
        value = script.expand(found.group(1), number, used)
        if value.startswith(BIOS + "/") and value[len(BIOS) + 1:] not in names:
            names.append(value[len(BIOS) + 1:])
        lines |= used
    if not names:
        raise script.missing(f"mkpfi of a file under {BIOS}")
    return [Launcher(
        emulator="piemu", build="standalone", kind="fixed_name", names=names,
        case_insensitive=False, search_dir=BIOS, passes_to="mkpfi argument",
        fails_when_missing=False,
        source_ref=source_ref([(RUNEMU, [table_line]), (path, lines)]),
    )]


def amiberry(read: Read, runemu: Runemu) -> list[Launcher]:
    """The kickstarts link of the package, and the ROM each default config names."""
    package = Script(AMIBERRY_PACKAGE, read(AMIBERRY_PACKAGE))
    links = [link for link in package.links(BIOS) if link.bios_is_target]
    if len(links) != 1 or links[0].bios_side.rstrip("/") != BIOS:
        raise package.missing(f"ln -s {BIOS} to the kickstarts folder")
    link = links[0]
    installed = re.sub(r"^\$\{INSTALL\}", "", link.link)
    path, table_line = runemu.script("AMIBERRY")
    script = Script(path, read(path))
    # A WHDLoad archive is booted by --autoload, which builds its own setup
    # over the config: the kickstart records hold for the other content.
    autoload = [n for n, text in script.code() if re.search(r"amiberry .*--autoload", text)]
    if not autoload:
        raise script.missing("WHDLoad boot with --autoload")
    content = (
        "content not booted with --autoload, a WHDLoad .lha or .zip "
        f"({posixpath.basename(path)}:{', '.join(map(str, autoload))})"
    )
    launchers = [Launcher(
        emulator="AMIBERRY", build="standalone", kind="links", names=[],
        case_insensitive=False, search_dir=BIOS,
        passes_to=f"{installed} is a symlink to it", fails_when_missing=False,
        source_ref=source_ref([(AMIBERRY_PACKAGE, link.lines)]),
    )]
    for number, line in script.code():
        copied = re.search(r"cp\s+\$AMIBERRY_CONFIG_DIR/(\S+\.uae)\s", line)
        if copied is None:
            continue
        config = f"{AMIBERRY_CONFIGS}/{copied.group(1)}"
        found = [
            s for s in settings(read(config))
            if s.key == "kickstart_rom_file" and s.value.startswith("$(FILE_PATH)/")
        ]
        rom_path = [s for s in settings(read(config)) if s.key == "amiberry.rom_path"]
        if len(found) != 1 or len(rom_path) != 1:
            raise LauncherPatternMissing(config, "kickstart_rom_file under $(FILE_PATH)")
        if rom_path[0].value.rstrip("/").rsplit("/", 1)[-1] != installed.rstrip("/").rsplit("/", 1)[-1]:
            raise LauncherPatternMissing(config, f"amiberry.rom_path naming {installed}")
        condition_line = max(
            n for n, text in script.code()
            if n < number and re.match(r"\s*(if|else)\b", text)
        )
        branch = script.lines[condition_line - 1].strip()
        if branch == "else":
            opened = max(
                n for n, text in script.code()
                if n < condition_line and re.match(r"\s*if\b", text)
            )
            test = _shell_test(script, opened)
            condition = f"not ({test})"
        else:
            test = _shell_test(script, condition_line)
            condition = test
        target = re.search(r'"?(\$\{?\w+\}?)"?\s*$', line)
        if target is None:
            raise script.missing(f"destination of the copy at line {number}")
        launchers.append(_evidence(read, Launcher(
            emulator="AMIBERRY", build="standalone", kind="fixed_name",
            slot=copied.group(1).removesuffix("-default.uae").removeprefix("Amiga"),
            names=[found[0].value.removeprefix("$(FILE_PATH)/")], case_insensitive=False,
            search_dir=BIOS,
            passes_to=f"{copied.group(1)} kickstart_rom_file, $(FILE_PATH) = {rom_path[0].value}",
            fails_when_missing=False,
            depends_on_option=f"{condition}, {content}",
            source_ref=source_ref([
                (RUNEMU, [table_line]), (path, [condition_line, number]),
                (config, [rom_path[0].line, found[0].line]),
            ]),
        ), script.expand(target.group(1), number, set()), ["kickstart_rom_file"],
            script, copied.group(1)))
    if len(launchers) == 1:
        raise script.missing("cp of a default .uae config")
    return launchers


def _shell_test(script: Script, line: int) -> str:
    """The test of `if <test>; then` at a line."""
    found = re.match(r"\s*if\s+(.*?);\s*then\s*$", script.lines[line - 1])
    if found is None:
        raise script.missing(f"if ...; then at line {line}")
    return found.group(1)


def scummvm(read: Read) -> list[Launcher]:
    """The paths scummvm.sh writes into the libretro core's scummvm.ini."""
    path = SCRIPTS["SCUMMVMSA"]
    script = Script(path, read(path))
    branch, _ = script.find(r'^\s*"libretro"\)', "libretro branch")
    launchers = []
    for number, line in script.code():
        if number < branch:
            continue
        written = re.search(r"s/\^/(\w*path)=((?:\\/[^\\/n]+)+)\\n/", line)
        if written is None:
            continue
        folder = written.group(2).replace("\\/", "/")
        if "/roms/bios/" not in folder + "/" or written.group(1) == "browser_lastpath":
            continue
        launchers.append(Launcher(
            emulator="scummvm", build="libretro", kind="passes_path", names=[],
            search_dir=folder, passes_to=f"scummvm.ini {written.group(1)}",
            fails_when_missing=False, depends_on_option="scummvm.sh libretro",
            source_ref=source_ref([(path, [branch, number])]),
        ))
    if not launchers:
        raise script.missing("a scummvm.ini path written under /roms/bios")
    return launchers


def freej2me(read: Read) -> list[Launcher]:
    """`if [ ! -f <bios>/<jar> ]; then cp <shipped jar> <bios>`."""
    launchers = []
    for core, path in FREEJ2ME:
        script = Script(path, read(path))
        tested, test = script.find(
            rf'if \[ ! -f "{re.escape(BIOS)}/([^"]+)" \]', "jar presence test"
        )
        jar = test.group(1)
        lines = [tested]
        source = None
        for number, line in script.code():
            copied = re.match(rf"\s*cp\s+(?:-\S+\s+)*(\S+/{re.escape(jar)})\s+{re.escape(BIOS)}/?\s*$", line)
            if copied:
                lines.append(number)
                source = copied.group(1)
        if source is None:
            raise script.missing(f"cp of {jar} into {BIOS}")
        launchers.append(Launcher(
            emulator=core, build="libretro", kind="copies", names=[jar],
            case_insensitive=False, search_dir=posixpath.dirname(source), passes_to=BIOS,
            fails_when_missing=False, source_ref=source_ref([(path, lines)]),
        ))
    return launchers


def easyrpg(read: Read) -> list[Launcher]:
    """Each install_bios call: a runtime package downloaded and unpacked under BIOS."""
    script = Script(EASYRPG, read(EASYRPG))
    url_line, url = script.find(r'curl -Lo "\$\{BIOS\}" "([^"]+)"', "curl of the package")
    launchers = []
    for number, line in script.code():
        call = re.match(r"\s*install_bios\s+(\S+)\s+(\S+)\s*$", line)
        if call is None:
            continue
        used: set[int] = {number, url_line}
        source = script.expand(url.group(1), number, used, {"BIOS": call.group(1)})
        install = script.value("INSTALLPATH", number)
        if install is None or install.value.rstrip("/") != BIOS:
            raise script.missing(f"INSTALLPATH {BIOS}")
        used.add(install.line)
        launchers.append(Launcher(
            emulator="easyrpg", build="libretro", kind="copies", names=[],
            search_dir=source, passes_to=f"{BIOS}/{call.group(2)}",
            fails_when_missing=False, source_ref=source_ref([(EASYRPG, used)]),
        ))
    if not launchers:
        raise script.missing("install_bios call")
    return launchers


def extract_launchers(read: Read) -> list[dict[str, Any]]:
    """Every launcher record, read through `read(repo-relative path)`."""
    runemu = Runemu(read)
    # The atari800.cfg AmberELEC ships names the OS ROMs, but the core opens
    # it only under its atari800_cfg option, off by default, and finds the
    # ROMs by a scan of the content folder (libretro-atari800 atari.c:512-516,
    # 537, libretro_core_options.h:1203): no record reads it.
    launchers = [
        *retroarch(read), *retrorun(read), *mame(runemu),
        *scummvm(read), *freej2me(read), *easyrpg(read),
        *amiberry(read, runemu), *hatari(read, runemu), *pico8(read, runemu),
        *piemu(read, runemu), *yabasanshiro(read, runemu),
    ]
    return [launcher.entry() for launcher in launchers]
