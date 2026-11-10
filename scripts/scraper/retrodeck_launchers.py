"""RetroDECK's launcher layer, read from each component's scripts.

A component's `component_prepare.sh` writes the emulator's config on reset:
melonDS gets seven fixed paths under $bios_path, xemu three, DuckStation and
PCSX2 a directory to search. It links folders the emulator reads into or out
of bios/ (LRPS2's pcsx2/bios points back at bios/, Dolphin's GC/<region>
folders live under saves/), and copies package-provided trees into bios/.
The presets it copies carry the rest: RetroArch core options that name a
BIOS file, XRoar's ROM search lists. RPCS3's firmware is downloaded by
RetroDECK itself and PICO-8 is started from a binary the user drops in bios/.

The shell is read as text, never run. Every line of a prepare or launcher
script that names $bios_path must match a known construct, else the scrape
stops with LauncherPatternMissing: an unclassified use would vanish from the
platform file without a word.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

try:
    from .retropie_launchers import Launcher, LauncherPatternMissing, merge_records, source_ref
except ImportError:
    from retropie_launchers import Launcher, LauncherPatternMissing, merge_records, source_ref

BIOS = "$bios_path"
PLACEHOLDER = "RETRODECKBIOSDIR"
# The roms folder in the same presets: GZDoom's IWADSearch.Directories holds
# RETRODECKROMSDIR/doom (gzdoom/rd_assets/rd_config/gzdoom.ini:9), which
# gzdoom/component_prepare.sh:27 rewrites to $roms_path.
ROMS_PLACEHOLDER = "RETRODECKROMSDIR"
CORE_OPTIONS = "retroarch/rd_assets/rd_config/retroarch-core-options.cfg"
# The component that runs libretro cores.
LIBRETRO_COMPONENT = "retroarch"
# Values of a core option that name a file rather than a setting.
_FILE_VALUE = re.compile(r"\.(bin|rom|img|zip|bios)$", re.IGNORECASE)
_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,6}$")
_ASSIGN = re.compile(r'^([A-Za-z_]\w*)="([^"]*)"$')
_GC_REGION = re.compile(r"/GC/(EUR|USA|JAP)$")

# Commands whose $bios_path argument creates or backs up a folder, logs, or
# only tests a path.
HOUSEKEEPING = frozenset({"create_dir", "log", "mkdir", "chmod", "rm", "unlink"})

Read = Callable[[str], "str | None"]


def _words(text: str) -> list[str]:
    try:
        return shlex.split(text, comments=True)
    except ValueError:
        return text.split()


def _unquote(value: str) -> str:
    return value.strip().strip("'\"")


def _split_path(path: str) -> tuple[str, str]:
    pure = PurePosixPath(path.rstrip("/"))
    return str(pure.parent), pure.name


def _is_file(path: str) -> bool:
    return bool(_EXTENSION.search(PurePosixPath(path).name))


def _mentions_bios(text: str) -> bool:
    return BIOS in text or "${bios_path}" in text


class Script:
    """One component shell script, line by line, with its enclosing tests."""

    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.lines = text.splitlines()

    def statements(self) -> list[tuple[int, list[str], str, list[str]]]:
        """(line, words, raw, enclosing conditions) for each command, `&&` chains split."""
        found = []
        branches: list[str] = []
        for number, line in enumerate(self.lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            opened = re.match(r"^(if|elif)\s+(.*?)\s*;\s*then\s*$", stripped)
            if opened is not None:
                condition = opened.group(2)
                if opened.group(1) == "if":
                    branches.append(condition)
                elif branches:
                    branches[-1] = condition
                continue
            if stripped == "else" and branches:
                branches[-1] = f"not ({branches[-1]})"
                continue
            if stripped == "fi":
                if branches:
                    branches.pop()
                continue
            shown = [c for c in branches if "$action" not in c]
            for part in re.split(r"\s+&&\s+|\s+\|\|\s+", stripped):
                words = _words(part)
                if words:
                    found.append((number, words, part, shown))
        return found


class Component:
    """What one component's scripts and presets hand its emulator."""

    def __init__(self, name: str, read: Read) -> None:
        self.name = name
        self.read = read
        self.build = "libretro" if name == LIBRETRO_COMPONENT else "standalone"
        self.records: list[Launcher] = []
        self.variables = self._variables()

    def _variables(self) -> dict[str, str]:
        text = self.read(f"{self.name}/component_functions.sh") or ""
        return {
            m.group(1): m.group(2)
            for m in (_ASSIGN.match(line.strip()) for line in text.splitlines())
            if m is not None
        }

    def resolve(self, word: str) -> str:
        """A word with the component's own bios/ paths filled in (`$retroarch_config_scummvm`)."""
        def fill(found: re.Match[str]) -> str:
            value = self.variables.get(found.group(1) or found.group(2), "")
            return value if _mentions_bios(value) else found.group(0)

        return re.sub(r"\$\{(\w+)\}|\$(\w+)", fill, word)

    def config_name(self, value: str) -> str:
        """`melonDS.toml` for `$melonds_config`, as component_functions.sh defines it."""
        variable = re.fullmatch(r"\$\{?(\w+)\}?", value)
        if variable is None or variable.group(1) not in self.variables:
            return value
        return PurePosixPath(self.variables[variable.group(1)]).name

    def record(
        self, kind: str, names: list[str], lines: list[tuple[str, int]], **fields: Any
    ) -> None:
        self.records.append(Launcher(
            emulator=fields.pop("emulator", self.name), build=fields.pop("build", self.build),
            kind=kind, names=names, source_ref=source_ref(lines), lines=list(lines), **fields,
        ))

    def read_prepare(self) -> None:
        path = f"{self.name}/component_prepare.sh"
        text = self.read(path)
        if text is None:
            return
        script = Script(path, text)
        settings: dict[tuple[str, ...], list[tuple[int, str, str]]] = {}
        copies: dict[tuple[str, str | None], list[tuple[int, str, str]]] = {}
        for number, words, raw, conditions in script.statements():
            depends = "; ".join(conditions) or None
            command = words[0]
            if command != "set_setting_value":
                words = [self.resolve(w) for w in words]
                raw = " ".join(words)
            if command == "set_setting_value" and len(words) >= 4:
                value = _unquote(words[3])
                if _mentions_bios(value):
                    section = words[5] if len(words) > 5 else None
                    where = f"[{section}] {words[2]}" if section else words[2]
                    target = self.config_name(words[1])
                    if _is_file(value):
                        settings.setdefault(("fixed_name", target, depends or ""), []).append(
                            (number, value, where)
                        )
                    else:
                        key = ("passes_path", target, where, depends or "")
                        settings.setdefault(key, []).append((number, value, where))
                continue
            if command == "dir_prep" and len(words) == 3:
                self._dir_prep(path, number, words[1], words[2], depends)
                continue
            if command == "ln" and _mentions_bios(raw):
                self._link(path, number, words, depends)
                continue
            if command == "cp" and len(words) >= 3 and _mentions_bios(words[-1]):
                source, target = words[-2], words[-1]
                folder, name = _split_path(source)
                copies.setdefault((folder, depends), []).append((number, name, target))
                continue
            if command == "tar" and "-C" in words and _mentions_bios(words[words.index("-C") + 1]):
                if "-czf" in words:
                    continue
                archive = next((w for w in words if w.endswith((".tar.gz", ".tgz", ".tar"))), None)
                if archive is None:
                    raise LauncherPatternMissing(
                        f"{path}:{number}", f"tar into bios/ of no archive: {raw}"
                    )
                self.record(
                    "copies", [], [(path, number)], search_dir=archive,
                    passes_to=words[words.index("-C") + 1], fails_when_missing=False,
                    depends_on_option=depends,
                )
                continue
            if command == "sed" and PLACEHOLDER in raw:
                self._preset(script, number, words)
                continue
            if not _mentions_bios(raw):
                continue
            if command in HOUSEKEEPING or command in ("[[", "[", "if") or command.startswith("[["):
                continue
            raise LauncherPatternMissing(
                f"{path}:{number}", f"unrecognised use of $bios_path: {raw}"
            )
        for key, hits in settings.items():
            self._settings(path, key, hits)
        for (folder, depends), hits in copies.items():
            names = [name for _n, name, _t in hits]
            targets = [target for _n, _name, target in hits]
            self.record(
                "copies", names, [(path, n) for n, _name, _t in hits], search_dir=folder,
                passes_to=_render_targets(names, targets), fails_when_missing=False,
                depends_on_option=depends or None,
            )

    def _settings(self, path: str, key: tuple[str, ...], hits: list[tuple[int, str, str]]) -> None:
        kind, target = key[0], key[1]
        depends = key[-1] or None
        lines = [(path, n) for n, _v, _w in hits]
        if kind == "fixed_name":
            folders = {_split_path(value)[0] for _n, value, _w in hits}
            if len(folders) != 1:
                raise LauncherPatternMissing(
                    f"{path}:{hits[0][0]}", "fixed names in several folders"
                )
            names = list(dict.fromkeys(_split_path(value)[1] for _n, value, _w in hits))
            wheres = list(dict.fromkeys(w for _n, _v, w in hits))
            self.record(
                "fixed_name", names, lines,
                case_insensitive=False, search_dir=folders.pop(),
                passes_to=f"{target} " + ", ".join(wheres),
                fails_when_missing=False, depends_on_option=depends,
            )
            return
        values = {v for _n, v, _w in hits}
        if len(values) != 1:
            raise LauncherPatternMissing(f"{path}:{hits[0][0]}", f"{key[2]} set to several folders")
        self.record(
            "passes_path", [], lines, search_dir=values.pop(),
            passes_to=f"{target} {key[2]}", fails_when_missing=False, depends_on_option=depends,
        )

    def _dir_prep(self, path: str, number: int, real: str, link: str, depends: str | None) -> None:
        """`dir_prep REAL LINK` makes LINK a symlink to REAL (functions/other_functions.sh)."""
        region = _GC_REGION.search(link)
        if region is not None:
            self.record(
                "links", [], [(path, number)], slot=region.group(1), search_dir=real,
                passes_to=f"{link} is a symlink to it", fails_when_missing=False,
                depends_on_option=depends,
            )
            return
        if real.startswith(BIOS):
            self.record(
                "links", [], [(path, number)], search_dir=real,
                passes_to=f"{link} is a symlink to it", fails_when_missing=False,
                depends_on_option=depends,
            )
        # A user folder (saves, textures, cheats) linked into bios/ hands no BIOS over.

    def _link(self, path: str, number: int, words: list[str], depends: str | None) -> None:
        paths = [w for w in words[1:] if not w.startswith("-")]
        if len(paths) != 2 or not _mentions_bios(paths[0]):
            raise LauncherPatternMissing(
                f"{path}:{number}", f"link without a bios/ source: {words}"
            )
        folder, name = _split_path(paths[0])
        self.record(
            "links", [name], [(path, number)], case_insensitive=False, search_dir=folder,
            passes_to=f"{paths[1]} is a symlink to it", fails_when_missing=False,
            depends_on_option=depends,
        )

    def _preset(self, script: Script, number: int, words: list[str]) -> None:
        """`sed -i "s#RETRODECKBIOSDIR#${bios_path}#g" "$cfg"` on a preset copied just above.

        Each line naming the BIOS or the roms folder is a record: a search
        list can mix them (XRoar's rompath, GZDoom's IWAD directories).
        """
        target = words[-1]
        substitutions = self._substitutions(script, target)
        copied = None
        for line_no, line in enumerate(script.lines[:number], 1):
            cp = _words(line.strip().split("&&")[0])
            if cp and cp[0] == "cp" and cp[-1] == target and "$component_config/" in cp[-2]:
                copied = (line_no, cp[-2].split("$component_config/", 1)[1])
        if copied is None:
            raise LauncherPatternMissing(f"{script.path}:{number}", f"no preset copied to {target}")
        preset = f"{self.name}/rd_assets/rd_config/{copied[1]}"
        text = self.read(preset)
        if text is None:
            raise LauncherPatternMissing(preset, "preset is missing")
        section = None
        found = 0
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if re.fullmatch(r"\[[^\]]+\]", stripped):
                section = stripped
            if stripped.startswith("#") or not any(
                p in stripped for p in (PLACEHOLDER, ROMS_PLACEHOLDER)
            ):
                continue
            setting = re.match(r"^([\w.$()-]+)\s*(?:=|\s)\s*(.+)$", stripped)
            if setting is None:
                raise LauncherPatternMissing(f"{preset}:{line_no}", f"placeholder in {stripped}")
            named = [p for p in substitutions if p in stripped]
            if PLACEHOLDER not in stripped and not named:
                # A roms placeholder the script leaves as written.
                continue
            key, value = setting.group(1), _unquote(setting.group(2))
            for placeholder, (variable, _line) in substitutions.items():
                value = value.replace(placeholder, variable)
            where = f"{section} {key}" if section else key
            found += PLACEHOLDER in stripped
            applied = [(script.path, copied[0]), (script.path, number)] + [
                (script.path, substitutions[p][1]) for p in named
            ]
            self.record(
                "passes_path", [], [(preset, line_no)] + applied,
                search_dir=value, passes_to=f"{self.config_name(target)} {where}",
                fails_when_missing=False,
            )
            if key == "rompath":
                self.romlists(preset, text, value, applied)
        if not found:
            raise LauncherPatternMissing(preset, f"no {PLACEHOLDER} line")

    @staticmethod
    def _substitutions(script: Script, target: str) -> dict[str, tuple[str, int]]:
        """Each placeholder sed rewrites in ``target``: (variable, line)."""
        found = {}
        for line_no, line in enumerate(script.lines, 1):
            for m in re.finditer(r"s#(RETRODECK\w+)#\$\{?(\w+)\}?#g[\"']?\s+\"([^\"]+)\"", line):
                if m.group(3) == target:
                    found[m.group(1)] = (f"${m.group(2)}", line_no)
        return found

    def romlists(
        self, preset: str, text: str, rompath: str, applied: list[tuple[str, int]]
    ) -> None:
        """XRoar's `romlist NAME=a,b,@other`: the names tried for each ROM, in order."""
        lists: dict[str, tuple[int, list[str]]] = {}
        for line_no, line in enumerate(text.splitlines(), 1):
            found = re.match(r"^romlist\s+([\w-]+)=(.*)$", line.strip())
            if found is not None:
                items = [_unquote(i) for i in re.findall(r'"[^"]*"|[^,]+', found.group(2))]
                lists[found.group(1)] = (line_no, items)
        if not lists:
            raise LauncherPatternMissing(preset, "rompath with no romlist")

        def expand(name: str, seen: tuple[str, ...]) -> list[str]:
            names = []
            for item in lists[name][1]:
                if item.startswith("@"):
                    ref = item[1:]
                    if ref not in lists or ref in seen:
                        raise LauncherPatternMissing(preset, f"romlist {name} refers to {item}")
                    names += expand(ref, seen + (ref,))
                else:
                    names.append(item)
            return list(dict.fromkeys(names))

        for name, (line_no, _items) in lists.items():
            self.record(
                "names_searched", expand(name, (name,)), [(preset, line_no)] + applied,
                slot=name, search_dir=rompath, passes_to=f"romlist {name}",
                fails_when_missing=False,
            )

    def read_launcher(self) -> None:
        path = f"{self.name}/component_launcher.sh"
        text = self.read(path)
        if text is None:
            return
        for number, words, raw, conditions in Script(path, text).statements():
            if not _mentions_bios(raw):
                continue
            if words[0] == "exec" and len(words) > 1 and _mentions_bios(words[1]):
                folder, name = _split_path(words[1])
                self.record(
                    "fixed_name", [name], [(path, number)], case_insensitive=False,
                    search_dir=folder, passes_to="exec", fails_when_missing=True,
                    depends_on_option="; ".join(conditions) or None,
                )
                continue
            raise LauncherPatternMissing(
                f"{path}:{number}", f"unrecognised use of $bios_path: {raw}"
            )

    def read_firmware_download(self) -> None:
        """A firmware URL RetroDECK downloads and hands to the emulator's installer."""
        path = f"{self.name}/component_functions.sh"
        text = self.read(path)
        if text is None:
            return
        urls = {
            name: value for name, value in self.variables.items()
            if re.match(r"https?://", value)
        }
        script = Script(path, text)
        statements = script.statements()
        for number, words, _raw, _conditions in statements:
            if words[0] != "download_file" or len(words) < 3:
                continue
            source = re.fullmatch(r"\$\{?(\w+)\}?", words[1])
            if source is None or source.group(1) not in urls:
                continue
            destination = words[2]
            installs = [
                (n, w) for n, w, _r, _c in statements
                if destination in w and w[0] != "download_file"
                and any(_installs(f) for f in w)
            ]
            if not installs:
                raise LauncherPatternMissing(
                    f"{path}:{number}", f"{destination} is downloaded but never installed"
                )
            install_line, install = installs[0]
            flag = next(f for f in install if _installs(f))
            function = self._function_at(script, number)
            assigned = next(
                n for n, line in enumerate(script.lines, 1)
                if line.strip().startswith(f"{source.group(1)}=")
            )
            folder, name = _split_path(destination)
            self.record(
                "fixed_name", [name], [(path, assigned), (path, number), (path, install_line)],
                case_insensitive=False, search_dir=folder,
                passes_to=f"component_launcher.sh {flag}", fails_when_missing=False,
                depends_on_option=f"{function} downloads {urls[source.group(1)]}",
            )

    @staticmethod
    def _function_at(script: Script, number: int) -> str:
        for line in reversed(script.lines[:number]):
            found = re.match(r"^([\w-]+)\s*\(\)\s*\{", line)
            if found is not None:
                return found.group(1)
        raise LauncherPatternMissing(f"{script.path}:{number}", "download outside a function")


def _installs(word: str) -> bool:
    """A launcher flag that installs a firmware file: RPCS3 --installfw, Vita3K --firmware."""
    return word.startswith("--install") or word == "--firmware"


def _render_targets(names: list[str], targets: list[str]) -> str:
    """Where copied names land: one folder when each keeps its name, else each path."""
    folders = {_split_path(t)[0] for t in targets}
    kept = [_split_path(t)[1] for t in targets] == [PurePosixPath(n).name for n in names]
    if kept and len(folders) == 1:
        return f"{folders.pop()}/<name>"
    return ", ".join(targets)


def core_options(read: Read) -> list[Launcher]:
    """RetroArch core options in RetroDECK's preset whose value names a BIOS file."""
    text = read(CORE_OPTIONS)
    prepare_path = f"{LIBRETRO_COMPONENT}/component_prepare.sh"
    prepare = read(prepare_path) or ""
    if text is None:
        raise LauncherPatternMissing(CORE_OPTIONS, "preset is missing")
    copied = [
        n for n, line in enumerate(prepare.splitlines(), 1)
        if "retroarch-core-options.cfg" in line and line.strip().startswith("cp ")
    ]
    if not copied:
        raise LauncherPatternMissing(prepare_path, "the core options preset is never copied")
    records = []
    for line_no, line in enumerate(text.splitlines(), 1):
        found = re.match(r'^([\w.-]+)\s*=\s*"([^"]*)"$', line.strip())
        if found is None or not _FILE_VALUE.search(found.group(2)):
            continue
        key, value = found.group(1), found.group(2)
        records.append(Launcher(
            emulator=LIBRETRO_COMPONENT, build="libretro", kind="core_option", names=[value],
            passes_to=f"core option {key}", fails_when_missing=False,
            source_ref=source_ref([(CORE_OPTIONS, line_no), (prepare_path, copied[0])]),
        ))
    if not records:
        raise LauncherPatternMissing(CORE_OPTIONS, "no core option names a file")
    return records


def extract_launchers(components: list[str], read: Read) -> list[dict[str, Any]]:
    """Every launcher record of the given components, read through `read(repo path)`.

    `read` returns None only for a file the component does not have.
    """
    records: list[Launcher] = []
    for name in components:
        component = Component(name, read)
        component.read_prepare()
        component.read_launcher()
        component.read_firmware_download()
        records += merge_records(component.records)
    if LIBRETRO_COMPONENT in components:
        records += core_options(read)
    if not records:
        raise LauncherPatternMissing("components", "no component hands a file to its emulator")
    return [record.entry() for record in records]
