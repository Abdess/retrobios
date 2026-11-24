"""Launcher records of one RetroPie package, from the statements its functions run."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .retropie_scripts import (
    Event,
    Launcher,
    LauncherPatternMissing,
    Module,
    Scripts,
    _FUNCTION,
    _split,
    source_ref,
)


BIOSDIR = "$biosdir"
# The roms root (retropie_packages.sh:47-49): MAME's mame.ini lists rom,
# sample and artwork folders below it (scriptmodules/emulators/mame.sh:133-136).
ROMDIR = "$romdir"


# The launch scripts copied next to an emulator spell the directory out.
BIOS_SPELLED = "RetroPie/BIOS"

# Commands whose $biosdir argument creates, owns or deletes a path and hands
# nothing to an emulator.
HOUSEKEEPING = frozenset({"mkUserDir", "chown", "chmod", "rm", "mkdir", "iniConfig"})

# Arguments that name a BIOS file or directory outside $biosdir, per package,
# as the emulator documents the flag. Each must still be in the scriptmodule.
OUTSIDE_BIOS: dict[str, tuple[str, ...]] = {
    "basilisk": ("--rom",),  # BasiliskII --rom <ROM file>
    "gngeopi": ("-B",),  # gngeo -B/--biospath <directory of neogeo.zip>
}

# Packages whose emulator reads its system files below the working directory
# the generated launch script enters with pushd: DraStic opens system/<name>
# under it, UAE4All2 kickstarts/<name> (its launchDir is getcwd()). Each must
# still pushd.
WORKING_DIRECTORY: tuple[str, ...] = ("drastic", "uae4all")


_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,5}$")


# The character each program splits a search list on, read in its code.
# AdvanceMAME strtoks dir_rom on file_dir_separator(), ':' on Linux, in all
# three builds RetroPie ships (advance/linux/file.c:138-141 and
# advance/osd/fileio.c:696-699 at 96237a5, 685-688 at advancemame-1.4,
# 640-643 in advancemame-0.94.0.tar.gz). MAME's path_iterator splits on ';'
# whatever the system (src/emu/fileio.cpp:56, 64, 112 at mame0289).
LIST_SEPARATORS = {"advmame": ":", "advmame-0.94": ":", "advmame-1.4": ":"}
DEFAULT_LIST_SEPARATOR = ";"


def _search_list_in_roms(event: Event, separator: str = DEFAULT_LIST_SEPARATOR) -> bool:
    """An iniSet whose value is a list of folders below the roms root.

    One folder alone is where a program writes (cfg_directory, nvram_directory
    and the others MAME's mame.ini sets): a list is where it searches, split
    on the separator the program reads it with.
    """
    if len(event.words) < 3 or len(event.words[2]) != 1:
        return False
    parts = [p for p in event.words[2][0].split(separator) if p]
    return len(parts) > 1 and all(
        p.startswith((ROMDIR + "/", "${romdir}/")) for p in parts
    )


def _mentions_bios(text: str) -> bool:
    return BIOSDIR in text or "${biosdir}" in text or BIOS_SPELLED in text


def _is_file(path: str) -> bool:
    return bool(_EXTENSION.search(PurePosixPath(path).name)) and "*" not in path


def _split_path(path: str) -> tuple[str, str]:
    pure = PurePosixPath(path.rstrip("/"))
    return str(pure.parent), pure.name


class PackageReader:
    """Launcher records of one package, from the statements its functions run."""

    def __init__(self, scripts: Scripts, package: Module) -> None:
        self.scripts = scripts
        self.package = package
        self.records: list[Launcher] = []
        self.installed_as: dict[str, str] = {}

    def record(
        self, kind: str, names: list[str], lines: list[tuple[str, int]], **fields: Any
    ) -> None:
        self.records.append(Launcher(
            emulator=fields.pop("emulator", self.package.id),
            package=self.package.id,
            build=self.package.build,
            kind=kind,
            names=names,
            source_ref=source_ref(lines),
            lines=list(lines),
            **fields,
        ))

    def final(self, path: str) -> str:
        """The file a scratch config ends up as, from the copyDefaultConfig that installs it."""
        return self.installed_as.get(path, path)

    def read(self) -> list[Launcher]:
        events = self.scripts.walk(self.package)
        for event in events:
            if (
                not event.heredoc and event.words and event.words[0] == ["copyDefaultConfig"]
                and len(event.words) >= 3 and len(event.words[1]) == 1 and len(event.words[2]) == 1
            ):
                self.installed_as.setdefault(event.words[1][0], event.words[2][0])
        links: list[Event] = []
        for event in events:
            if not event.words or not event.words[0]:
                continue
            if links and not self._same_link_run(links[-1], event):
                self._links(links)
                links = []
            if self._is_bios_link(event):
                links.append(event)
                continue
            self._classify(event)
        if links:
            self._links(links)
        self._outside_bios(events)
        self._working_directory(events)
        self._reaching_links(events)
        return self.records

    @staticmethod
    def _depends(event: Event) -> str | None:
        return "; ".join(event.conditions) if event.conditions else None

    def _classify(self, event: Event) -> None:
        command = event.words[0][0]
        if event.heredoc:
            if _mentions_bios(event.raw):
                self._heredoc_setting(event)
            return
        if command == "addEmulator":
            self._add_emulator(event)
            return
        if command == "iniSet" and not _mentions_bios(event.raw):
            # A search path below the roms root: MAME reads its samples from
            # samplepath $romdir/mame/samples;$romdir/arcade/samples.
            if _search_list_in_roms(
                event, LIST_SEPARATORS.get(self.package.id, DEFAULT_LIST_SEPARATOR)
            ):
                self._ini_set(event)
            return
        if not _mentions_bios(event.raw):
            return
        if command in HOUSEKEEPING:
            return
        handlers = {
            "cp": self._copy,
            "runCmd": self._run_cmd,
            "unzip": self._unzip,
            "mv": self._move,
            "moveConfigFile": self._move,
            "moveConfigDir": self._move_dir,
            "iniSet": self._ini_set,
            "copyDefaultConfig": self._written,
            "cat": self._written,
            "echo": self._written,
            "cmake": self._build_flag,
        }
        handler = handlers.get(command)
        if handler is None:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"unrecognised use of the BIOS directory: {event.raw}"
            )
        handler(event)

    def _is_bios_link(self, event: Event) -> bool:
        words = event.words
        if words[0][0] != "ln" or not _mentions_bios(event.raw):
            return False
        paths = [w for w in words[1:] if not w[0].startswith("-")]
        if len(paths) != 2 or not all(_mentions_bios(v) for v in paths[0]):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"link without a BIOS source: {event.raw}"
            )
        return True

    @staticmethod
    def _same_link_run(previous: Event, event: Event) -> bool:
        return (
            event.words[0][0] == "ln"
            and previous.path == event.path
            and event.line - previous.line <= 2
        )

    def _links(self, events: list[Event]) -> None:
        sources: list[str] = []
        targets: list[str] = []
        for event in events:
            paths = [w for w in event.words[1:] if not w[0].startswith("-")]
            source, target = paths
            if len(target) == 1 and len(source) > 1:
                target = [f"{target[0].rstrip('/')}/{_split_path(s)[1]}" for s in source]
            sources += source
            targets += target
        folders = {_split_path(s)[0] for s in sources}
        whole_dir = all(
            not _is_file(s) and "/" not in s.replace(BIOSDIR, "", 1).strip("/") for s in sources
        )
        if whole_dir:
            names: list[str] = []
            search_dir = sources[0]
            passes_to = f"{targets[0]} is a symlink to it"
        else:
            if len(folders) != 1:
                raise LauncherPatternMissing(
                    f"{events[0].path}:{events[0].line}",
                    "links from several BIOS folders in one run",
                )
            search_dir = folders.pop()
            names = [_split_path(s)[1] for s in sources]
            passes_to = _render_targets(names, targets)
        self.record(
            "links", names, [(e.path, e.line) for e in events],
            case_insensitive=False, search_dir=search_dir, passes_to=passes_to,
            fails_when_missing=False, depends_on_option=self._depends(events[0]),
        )

    def _copy(self, event: Event) -> None:
        paths = [v for w in event.words[1:] if not w[0].startswith("-") for v in w]
        *sources, target = paths
        if not _mentions_bios(target):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"copy out of the BIOS directory: {event.raw}"
            )
        folders = {_split_path(s)[0] for s in sources}
        if len(folders) != 1:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", "copy from several folders")
        self.record(
            "copies", [_split_path(s)[1] for s in sources], [(event.path, event.line)],
            search_dir=folders.pop(), passes_to=target.rstrip("/"),
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _run_cmd(self, event: Event) -> None:
        inner = Event(event.path, event.line, event.words[1:], event.raw, event.conditions, False)
        if not inner.words or inner.words[0][0] != "unzip":
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"runCmd of {event.raw}")
        self._unzip(inner)

    def _unzip(self, event: Event) -> None:
        values = [v for w in event.words[1:] for v in w]
        if "-d" not in values:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", "unzip without -d")
        target = values[values.index("-d") + 1]
        archives = [v for v in values if v.endswith(".zip")]
        if len(archives) != 1 or not _mentions_bios(target):
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"unzip of {event.raw}")
        self.record(
            "copies", [], [(event.path, event.line)],
            search_dir=archives[0], passes_to=target,
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _move(self, event: Event) -> None:
        source, target = (w for w in event.words[1:] if not w[0].startswith("-"))
        if not all(_mentions_bios(v) for v in source + target):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"move across folders: {event.raw}"
            )
        folders = {_split_path(s)[0] for s in source}
        destinations = {_split_path(t)[0] for t in target}
        if len(folders) != 1 or len(destinations) != 1:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", "move between several folders"
            )
        self.record(
            "moves", [_split_path(s)[1] for s in source], [(event.path, event.line)],
            case_insensitive=False, search_dir=folders.pop(), passes_to=destinations.pop(),
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _move_dir(self, event: Event) -> None:
        link, real = (w[0] for w in event.words[1:3])
        if not _mentions_bios(real) or _mentions_bios(link):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"moveConfigDir into a non-BIOS folder: {event.raw}"
            )
        self.record(
            "links", [], [(event.path, event.line)],
            search_dir=real, passes_to=f"{link} is a symlink to it",
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _ini_set(self, event: Event) -> None:
        key, value = event.words[1][0], event.words[2][0]
        target = self._ini_file(event)
        passes_to = f"{key} in {self.final(target)}" if target else key
        if _is_file(value) and ";" not in value:
            folder, name = _split_path(value)
            self.record(
                "fixed_name", [name], [(event.path, event.line)],
                case_insensitive=False, search_dir=folder, passes_to=passes_to,
                fails_when_missing=False, depends_on_option=self._depends(event),
            )
            return
        self.record(
            "passes_path", [], [(event.path, event.line)],
            search_dir=value, passes_to=passes_to,
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _ini_file(self, event: Event) -> str | None:
        """The file the closest iniConfig above this iniSet points at."""
        if len(event.words) > 3:
            return event.words[3][0]
        lines = self.scripts.files[event.path].splitlines()
        for number in range(event.line - 1, 0, -1):
            words = _split(lines[number - 1].strip())
            if words and words[0] == "iniConfig" and len(words) >= 4:
                return words[3]
            if _FUNCTION.match(lines[number - 1]):
                break
        return None

    def _written(self, event: Event) -> None:
        """A file the package writes into the BIOS directory itself."""
        target = next(
            (v for w in reversed(event.words[1:]) for v in w if _mentions_bios(v)), None
        )
        if target is None or not _is_file(target):
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"write of {event.raw}")
        folder, name = _split_path(target)
        self.record(
            "copies", [name], [(event.path, event.line)],
            search_dir=None, passes_to=folder,
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _build_flag(self, event: Event) -> None:
        flags = [
            v for w in event.words[1:] for v in w
            if v.startswith("-D") and "=" in v and _mentions_bios(v)
        ]
        if not flags:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"cmake of {event.raw}")
        for flag in flags:
            option, value = flag.split("=", 1)
            self.record(
                "passes_path", [], [(event.path, event.line)],
                search_dir=value, passes_to=f"build option {option}",
                fails_when_missing=False, depends_on_option=self._depends(event),
            )

    def _heredoc_setting(self, event: Event) -> None:
        """A `KEY = $biosdir/...` or `--flag="$biosdir"` line of a generated file."""
        text = event.raw
        setting = re.match(r'^([\w.-]+)\s*=\s*"?([^"]*)"?$', text)
        flag = re.match(r'^(--?[\w-]+)(?:=|\s+)"?([^"]*)"?$', text)
        found = flag or setting
        if found is None:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"generated line names the BIOS directory: {text}"
            )
        key, value = found.group(1), found.group(2)
        kind, names, folder = "passes_path", [], value
        if _is_file(value):
            folder, name = _split_path(value)
            kind, names = "fixed_name", [name]
        written = _redirect_target(event.opener)
        if written is None:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", "generated file with no > or >> target"
            )
        self.record(
            kind, names, [(event.path, event.line)],
            case_insensitive=False if kind == "fixed_name" else None,
            search_dir=folder, passes_to=f"{key} in {self.final(written)}",
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _add_emulator(self, event: Event) -> None:
        if len(event.words) < 5:
            return
        command = event.words[4][0]
        if not _mentions_bios(command):
            return
        names = event.words[2]
        tokens = _split(command)
        found = [
            (flag, value) for flag, value in zip(tokens, tokens[1:])
            if flag.startswith("-") and _mentions_bios(value)
        ]
        found += [
            (head, tail) for head, sep, tail in (token.partition("=") for token in tokens)
            if head.startswith("-") and sep and _mentions_bios(tail)
        ]
        if not found:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}",
                f"addEmulator names the BIOS directory without a flag: {command}",
            )
        for emulator in names:
            for flag, value in found:
                self._command_line(event, emulator, flag, value)

    def _command_line(self, event: Event, emulator: str, flag: str, value: str) -> None:
        folder, name = _split_path(value)
        if _is_file(value):
            kind, names, search = "fixed_name", [name], folder
        else:
            kind, names, search = "passes_path", [], value
        self.record(
            kind, names, [(event.path, event.line)], emulator=emulator,
            case_insensitive=False if kind == "fixed_name" else None,
            search_dir=search, passes_to=f"command line {flag}",
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _outside_bios(self, events: list[Event]) -> None:
        flags = OUTSIDE_BIOS.get(self.package.id)
        if not flags:
            return
        seen: set[str] = set()
        for event in events:
            if event.words[0][0] != "addEmulator" or len(event.words) < 5:
                continue
            tokens = _split(event.words[4][0])
            for flag, value in zip(tokens, tokens[1:]):
                if flag in flags:
                    seen.add(flag)
                    for emulator in event.words[2]:
                        self._command_line(event, emulator, flag, value)
        missing = sorted(set(flags) - seen)
        if missing:
            raise LauncherPatternMissing(
                self.package.path, f"addEmulator no longer passes {missing}"
            )


    def _reaching_links(self, events: list[Event]) -> None:
        """The directories outside the BIOS one that a whole-directory link lies in.

        openmsx's moveConfigDir "$home/.openMSX" "$configdir/msx/openmsx"
        puts the emulator's directory where the systemroms link to BIOS/openmsx
        lies, and xroar's ./configure --prefix="$md_inst" builds the program
        whose share/xroar/roms links to $biosdir. Neither line names the BIOS
        directory, and each says where the link is read from.
        """
        suffix = " is a symlink to it"
        linked = [
            (record.passes_to or "").removesuffix(suffix).rstrip("/")
            for record in self.records
            if record.kind == "links" and not record.names
            and (record.passes_to or "").endswith(suffix)
        ]
        if not linked:
            return

        def holds(directory: str) -> bool:
            directory = directory.strip("\"'").rstrip("/")
            return bool(directory) and any(
                path == directory or path.startswith(directory + "/") for path in linked
            )

        for event in events:
            if event.heredoc or not event.words or _mentions_bios(event.raw):
                continue
            command = event.words[0][0]
            if command == "moveConfigDir" and len(event.words) >= 3:
                link, real = event.words[1][0], event.words[2][0]
                if holds(real):
                    self.record(
                        "links", [], [(event.path, event.line)],
                        search_dir=real, passes_to=f"{link}{suffix}",
                        fails_when_missing=False, depends_on_option=self._depends(event),
                    )
            elif command.endswith("configure"):
                for word in event.words[1:]:
                    prefix = word[0].strip("\"'")
                    if prefix.startswith("--prefix=") and holds(prefix[len("--prefix="):]):
                        self.record(
                            "passes_path", [], [(event.path, event.line)],
                            search_dir=prefix[len("--prefix="):].strip("\"'"),
                            passes_to="${prefix} of configure --prefix",
                            fails_when_missing=False, depends_on_option=self._depends(event),
                        )

    def _working_directory(self, events: list[Event]) -> None:
        """The folder a generated launch script enters before it runs the emulator."""
        if self.package.id not in WORKING_DIRECTORY:
            return
        found = False
        for event in events:
            if not event.heredoc or not event.words or event.words[0] != ["pushd"]:
                continue
            script = _redirect_target(event.opener)
            if script is None or len(event.words) != 2 or len(event.words[1]) != 1:
                raise LauncherPatternMissing(
                    f"{event.path}:{event.line}", f"pushd outside a launch script: {event.raw}"
                )
            found = True
            self.record(
                "passes_path", [], [(event.path, event.line)],
                search_dir=event.words[1][0].strip("\"'"),
                passes_to=f"working directory of {script}",
                fails_when_missing=False, depends_on_option=self._depends(event),
            )
        if not found:
            raise LauncherPatternMissing(
                self.package.path, "the launch script no longer enters a working directory"
            )


def _redirect_target(words: list[list[str]]) -> str | None:
    """The file a `cat > FILE << EOF` or `cat << EOF >> FILE` line writes."""
    flat = [w[0] for w in words if w]
    for index, word in enumerate(flat[:-1]):
        if word in (">", ">>"):
            return flat[index + 1]
    return None


def _render_targets(names: list[str], targets: list[str]) -> str:
    """Where linked names land: one folder when the names are kept, each path when renamed."""
    folders = {_split_path(t)[0] for t in targets}
    kept = [_split_path(t)[1] for t in targets] == names
    if kept and len(folders) == 1:
        return f"{folders.pop()}/<name>"
    return ", ".join(targets)
