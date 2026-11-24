"""RetroPie's launcher layer, read from the scriptmodules.

RetroPie publishes no BIOS list, but its package scripts decide where a file
dropped in ~/RetroPie/BIOS ends up: px68k links five names into ~/.keropi,
redream links dc_boot.bin under another name, sdltrs passes one ROM per
machine on its command line, the fs-uae launch script refuses to start
without kick13.rom. Each package also says which project it builds
(`rp_module_repo`) and which systems it registers (`addSystem`), which is
what ties a package to the emulator profile describing that build.

The bash is read as text, never run. A small evaluator follows what the
scripts do between a function's braces: local assignments, arrays, `for`
loops, brace expansion, `$md_id` and calls into other packages' functions,
the way RetroPie runs them in one shell. Every line of a package function
that names the BIOS directory must match a known construct, else the scrape
stops with LauncherPatternMissing: a use nobody classified would otherwise
drop out of the platform file without a word.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .retropie_reader import PackageReader, mentions_bios, split_path
from .retropie_scripts import (
    Launcher,
    LauncherPatternMissing,
    Module,
    SCRIPTMODULES,
    SECTIONS,
    Scripts,
    VAR,
    merge_records,
    source_ref,
)

PACKAGES_SCRIPT = "retropie_packages.sh"


def package_record(scripts: Scripts, package: Module) -> Launcher:
    """What the package builds and the systems it registers."""
    systems: list[str] = []
    lines: list[tuple[str, int]] = [(package.path, package.id_line)]
    if package.repo_line is not None:
        lines.append((package.path, package.repo_line))
    for event in scripts.walk(package):
        if event.heredoc or not event.words or not event.words[0]:
            continue
        command = event.words[0][0]
        if command == "addSystem":
            values = event.words[1] if len(event.words) > 1 else []
        elif command == "addPort":
            values = ["ports"]
        else:
            continue
        if not values:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"{command} takes no value")
        for value in values:
            if "$" in value or not value:
                raise LauncherPatternMissing(
                    f"{event.path}:{event.line}", f"system name {value!r} not resolved"
                )
            if value not in systems:
                systems.append(value)
        lines.append((event.path, event.line))
    return Launcher(
        emulator=package.id, package=package.id, repo=package.repo,
        systems=systems or None, build=package.build, kind="package", names=[],
        source_ref=source_ref(lines),
    )


def launch_script_records(scripts: Scripts) -> list[Launcher]:
    """The launch scripts installed next to an emulator that refuse to start without a file."""
    records = []
    for path, text in sorted(scripts.files.items()):
        parts = PurePosixPath(path).parts
        is_script = (
            len(parts) == 4 and parts[0] == SCRIPTMODULES and parts[1] in SECTIONS
            and path.endswith(".sh")
        )
        if not is_script or not mentions_bios(text):
            continue
        package = scripts.modules.get(parts[2])
        if package is None:
            raise LauncherPatternMissing(path, f"launch script of no package {parts[2]}")
        records += _launch_script(path, text.splitlines(), package)
    return records


def _launch_script(path: str, lines: list[str], package: Module) -> list[Launcher]:
    env: dict[str, str] = {"HOME": "$HOME"}
    records = []
    checks = 0
    number = 0
    while number < len(lines):
        number += 1
        stripped = lines[number - 1].strip()
        if not stripped or stripped.startswith("#"):
            continue
        assign = re.match(r'^([A-Za-z_]\w*)="([^"]*)"$', stripped)
        if assign is not None:
            env[assign.group(1)] = VAR.sub(
                lambda m: env.get(m.group(1) or m.group(3), m.group(0)), assign.group(2)
            )
            continue
        check = re.match(r'^if \[\[ ! -f "([^"]+)" \]\]; then$', stripped)
        if check is None:
            continue
        tested = check.group(1)
        resolved = VAR.sub(lambda m: env.get(m.group(1) or m.group(3), m.group(0)), tested)
        if not mentions_bios(resolved):
            continue
        block_start = number
        message: str | None = None
        exits = False
        while number < len(lines) and lines[number].strip() != "fi":
            number += 1
            body = lines[number - 1].strip()
            exits = exits or body == "exit 1"
            pause = re.search(r'--pause "([^"]*)"', body)
            if pause is not None:
                message = pause.group(1)
        number += 1
        if not exits:
            continue
        checks += 1
        variable = re.fullmatch(r"\$\{?(\w+)\}?", tested)
        passes_to = None
        cited = list(range(block_start, number + 1))
        if variable is not None:
            for later, line in enumerate(lines[number:], number + 1):
                flag = re.search(r'(--?[\w-]+)="\$' + variable.group(1) + r'"', line)
                if flag is not None:
                    passes_to = f"command line {flag.group(1)}"
                    cited.append(later)
                    break
        folder, name = split_path(resolved)
        records.append(Launcher(
            emulator=package.id, package=package.id, build=package.build,
            kind="fixed_name", names=[name], case_insensitive=False,
            search_dir=folder, passes_to=passes_to,
            fails_when_missing=message if message is not None else True,
            source_ref=source_ref([(path, n) for n in cited]),
        ))
    if not checks:
        raise LauncherPatternMissing(path, "names the BIOS directory but checks no file")
    return records


def extract_launchers(files: dict[str, str]) -> list[dict[str, Any]]:
    """Every launcher record, from the scriptmodules keyed by repo-relative path."""
    scripts = Scripts(files)
    records: list[Launcher] = []
    for package in sorted(scripts.modules.values(), key=lambda m: m.path):
        records.append(package_record(scripts, package))
        records += merge_records(PackageReader(scripts, package).read())
    records += launch_script_records(scripts)
    return [record.entry() for record in records]
