"""What the installer pages and the README state holds against install.py.

Each class reads a page and the code it describes: run samples, options,
exit codes, variables and the folders a first install writes to.
"""

from __future__ import annotations

import tests
from tests.mdsections import FENCED
from tests.sources import declared_options, script_source

import ast
import inspect
import json
import re
import unittest

from tests.docpagessupport import PUBLISHED, ROOT, WIKI, _page, _section, _table_rows


def _generated(text: str, name: str) -> str:
    """The body scripts/generate_installer_doc.py writes between the markers."""
    body = re.search(rf"(?s)<!-- generated: {name} -->\n(.*?)<!-- /generated: {name} -->", text)
    assert body is not None, f"no generated: {name} markers"
    return body.group(1)


class InstallerOutputExample(unittest.TestCase):
    """The page showed a run with no `Not installable:` line while the
    RetroArch manifest left eleven entries out, and a count that the menu
    example below it no longer shared. Its run samples were then typed by
    hand and compared here, so a new list left the page stale and this test
    red until someone retyped them: scripts/generate_installer_doc.py now
    prints each one with install.py from the committed list."""

    def test_the_samples_are_the_ones_the_installer_prints(self):
        from installer_build import installerdoc

        page = _page("installer.md")
        self.assertEqual(installerdoc.render(page), page,
                         "run python scripts/generate_installer_doc.py")
        for name in ("dry-run", "run-date", "run-index", "run-download", "run-end", "run-check"):
            with self.subTest(sample=name):
                self.assertIn(f"<!-- generated: {name} -->", page)

    def test_a_retyped_count_fails_the_check(self):
        from installer_build import installerdoc

        page = _page("installer.md")
        for name in ("dry-run", "run-end", "bulk-hint"):
            with self.subTest(sample=name):
                body = _generated(page, name)
                edited = re.sub(r"\d+", lambda m: str(int(m.group(0)) + 1), body, count=1)
                stale = page.replace(body, edited)
                self.assertNotEqual(stale, page)
                self.assertEqual(installerdoc.render(stale), page)

    def test_a_sample_is_dated_by_its_list_never_by_the_day_it_ran(self):
        from installer_build import installerdoc

        page = _page("installer.md")
        for name, platform in (("dry-run", "retroarch"), ("run-date", "batocera")):
            with self.subTest(sample=name):
                listed = (ROOT / "install" / f"{platform}.json").read_text(encoding="utf-8")
                date = json.loads(listed)["generated"][:10]
                self.assertIn(f"the list of {date}", _generated(page, name))
        self.assertNotIn(str(ROOT), page)
        home = f"{installerdoc.SHOWN_HOME}/.config/retroarch"
        self.assertIn(home, _generated(page, "dry-run"))

    def test_run_and_menu_show_one_run_of_the_manifest(self):
        import install

        text = _page("installer.md")
        run = _generated(text, "dry-run")
        manifest = json.loads((ROOT / "install" / "retroarch.json").read_text(encoding="utf-8"))
        # The line as the installer writes it (not_installable_words), or
        # its earlier "(1 required, not found: 37)" form.
        omitted = re.search(r"Not installable: \d+ files?(?: \(\d+ required, (.*)\)\.| (?:is|are) "
                            r"not in the collection|.*Why: (.*)\.)", run)
        self.assertEqual(omitted is not None, bool(manifest.get("omitted_files")))
        if omitted and (omitted.group(1) or omitted.group(2)):
            for part in (omitted.group(1) or omitted.group(2)).split(", "):
                self.assertIn(re.split(r":| \(", part)[0], install.OMISSION_REASONS.values())
        count, size = re.search(r"\n  (\d+) files \(([\d.]+ [KMG]B)\)", run).groups()
        self.assertIn(f"0 in place, {count} missing", run)
        self.assertSplitAddsUp(run, count, size)
        menu = re.search(r"RetroArch: (\d+) files, ([\d.]+ [KMG]B)[.,]([^`]*)",
                         _generated(text, "line-menu"))
        self.assertEqual(menu.groups()[:2], (count, size))
        self.assertSplitAddsUp(menu.group(3), count, size)
        games = re.search(r"g\) Game data: kept \((\d+) files, ([\d.]+ [KMG]B)\)",
                          menu.group(3))
        self.assertIsNotNone(games, "the menu offers to leave the game data out")
        split = re.search(r"(\d+) BIOS files \(([\d.]+ [KMG]B)\)(?:,| and) (\d+) game data "
                          r"files \(([\d.]+ [KMG]B)\)", menu.group(3))
        self.assertEqual(games.groups(), split.groups()[2:])

    def assertSplitAddsUp(self, text: str, count: str, size: str) -> None:
        """The run counted 8069 files where its menu counted 3259 BIOS files
        and 5089 game data files: the parts add up to the total they divide,
        the sizes within the rounding of their three figures."""
        # Data files are a third kind, counted beside the two.
        split = re.search(r"(\d+) BIOS files \(([\d.]+) ([KMG]B)\)(?:,| and) (\d+) game data "
                          r"files \(([\d.]+) ([KMG]B)\)", text)
        self.assertIsNotNone(split, "a categorized list says its BIOS files and game data")
        assert split is not None
        bios, bios_size, bios_unit, games, game_size, game_unit = split.groups()
        # The data files in the one total, the third kind.
        data = re.search(r"and (\d+) data files \(([\d.]+) ([KMG]B)\)", text)
        data_count, data_size, data_unit = data.groups() if data else ("0", "0", "KB")
        self.assertEqual(int(bios) + int(games) + int(data_count), int(count))
        units = {"KB": 1, "MB": 1024, "GB": 1024 ** 2}
        total, unit = size.split()
        added = (float(bios_size) * units[bios_unit] + float(game_size) * units[game_unit]
                 + float(data_size) * units[data_unit])
        self.assertLessEqual(abs(added - float(total) * units[unit]), 0.15 * units[unit])


class InstallerSamplesSayWhatTheCodePrints(unittest.TestCase):
    """Samples typed by hand outside the
    generated blocks, a sentence on a log read as the terminal's, pages that
    described the generator as tables alone, and a sandbox that asked DNS."""

    def test_the_refused_and_from_samples_are_generated(self):
        import install

        page = _page("installer.md")
        refused = _generated(page, "check-refused")
        self.assertRegex(refused, r"\n  \d+ files? [a-z ]+\.\n")
        self.assertIn("read by beetle_psx, pcsx_rearmed at", refused)
        self.assertNotRegex(page, r"opened at /\S+ by ")
        self.assertIn('"read by ', inspect.getsource(install.opened_line))
        ending = _generated(page, "from-run")
        self.assertRegex(ending, r"Done\. \d+ files installed\.\n  \d+ files copied from ")
        self.assertNotIn("a line under\n`Done`", page)
        self.assertNotIn("38 files copied from E:\\, 4 downloaded", page)

    def test_one_line_per_file_is_said_of_a_log(self):
        page = _page("installer.md")
        at = page.index("<!-- generated: run-download -->")
        before = page[page.rindex("\n\n", 0, at - 2):at]
        self.assertIn("At a terminal one progress line", before)
        self.assertIn("a pipe or a log gets one\nline per file", before)

    def test_the_generator_pages_name_the_run_samples_and_step_7(self):
        tools = _page("tools.md")
        row = next(line for line in tools.splitlines()
                   if line.startswith("| `generate_installer_doc.py`"))
        self.assertIn("run samples", row)
        self.assertIn("generate_installer_doc.py", next(
            line for line in tools.splitlines() if line.startswith("| 7 |")))
        self.assertIn("run samples", _page("installer.md").split(
            "The tables of options, events, exit codes, keys and card markers", 1)[1][:600])
        self.assertIn("generate_installer_doc.py", next(
            line for line in _page("adding-a-platform.md").splitlines()
            if line.startswith("- 7 ")))

    def test_the_sandbox_looks_nothing_up(self):
        import socket
        from unittest import mock

        from installer_build import installerdoc

        def no_lookup(*_args: object) -> str:
            raise AssertionError("the sandbox asked for a name")

        with mock.patch.object(socket, "getfqdn", no_lookup), \
                installerdoc.Sandbox() as box:
            self.assertEqual(box.server.server_name, "127.0.0.1")


class ReleaseRefPromise(unittest.TestCase):
    """RETROBIOS_REF was said to pin a reproducible file set, while every
    release deletes the previous tags and large files come from one fixed
    release whatever the ref."""

    def test_the_page_says_what_a_tag_does_not_pin(self):
        import install

        self.assertIn("/large-files/", install.RELEASE_URL)
        self.assertIn("--cleanup-tag", _page("release-process.md"))
        row = next(
            line for line in _page("installer.md").splitlines()
            if line.startswith("| `RETROBIOS_REF`")
        )
        self.assertIn("`large-files`", row)
        self.assertIn("next release", row)
        for page in PUBLISHED:
            for paragraph in page.read_text(encoding="utf-8").split("\n\n"):
                if "RETROBIOS_REF" in paragraph:
                    self.assertNotIn("reproducible", paragraph, page.name)


class ReleaseCommitCarriesTheManifests(unittest.TestCase):
    """The documented release commit left out install/*.json, which the
    release pipeline regenerates: v2026.10.10 added three by hand."""

    def test_the_commit_step_adds_what_the_pipeline_rewrites(self):
        pipeline = script_source("pipeline.py")
        self.assertIn('"--manifest"', pipeline)
        block = _section(_page("release-process.md"), "Cutting a release")
        add = next(line for line in block.splitlines() if line.startswith("git add "))
        self.assertIn("install/*.json", add.split())


def _calls(source: str, opening: str) -> list[str]:
    """The text of each call that starts with *opening*, to its closing parenthesis."""
    calls = []
    start = source.find(opening)
    while start != -1:
        depth, end = 0, start + len(opening) - 1
        while end < len(source):
            depth += {"(": 1, ")": -1}.get(source[end], 0)
            if depth == 0:
                break
            end += 1
        calls.append(source[start:end + 1])
        start = source.find(opening, end)
    return calls


class ExitStatusTable(unittest.TestCase):
    """Code 2 was documented as 'every file failed' only, while argparse
    exits 2 on every refused option, and the 141 example named an option
    that does not exist."""

    def test_codes_and_options_are_the_installers(self):
        source = (ROOT / "install.py").read_text(encoding="utf-8")
        section = _section(_page("installer.md"), "Exit status")
        documented = {int(row[0].strip("`")) for row in _table_rows(section)}
        raised = {int(code) for code in re.findall(r"sys\.exit\((\d+)\)", source)}
        # A refusal leaves with the code it carries (installer/refusal.py).
        raised |= {int(code) for call in _calls(source, "raise Refusal(")
                   for code in re.findall(r"\bcode=(\d+)", call)}
        # 0 is a run that returns, 2 the code argparse leaves with.
        self.assertEqual(documented, raised | {0, 2})
        self.assertIn("install.py: error:", section)
        for option in set(re.findall(r"(--[a-z][a-z-]+)", section)):
            self.assertIn(f'"{option}"', source, option)


class PythonFloorOnRetroPie(unittest.TestCase):
    """The page offered `apt install python3` to a RetroPie 4.8 image, where
    python3 is 3.7.3 and apt has nothing newer."""

    def test_both_pages_name_the_case(self):
        install_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("(3, 8)", install_sh)
        first = _section(_page("first-install.md"), "Error: Python 3.8 or newer is required.")
        self.assertIn("RetroPie 4.8", first)
        self.assertIn("3.7.3", first)
        changing = _section(_page("installer.md"), "Changing the installer")
        self.assertIn("3.7.3", changing)


class ReadmeInstallerOptions(unittest.TestCase):
    """The README named --system, --region and --check but showed options
    only after `sh -s --`. Appended to `irm ... | iex`, PowerShell rejects
    them, and the form that works was on the installer page alone, which the
    README never linked."""

    def test_quick_install_gives_the_powershell_form_and_the_page(self):
        from sitegen import readme as sitegen_readme
        from tests.readmeinputs import readme_inputs

        readme = sitegen_readme.render_readme(readme_inputs())
        self.assertIn("## Passing options", _page("installer.md"))
        quick = _section(readme, "Install in one line")
        # The README gives the bare line and sends options to the page that
        # writes their PowerShell form: an option after `| iex` reaches iex.
        self.assertIn("wiki/installer/#passing-options", quick)
        self.assertNotRegex(readme, r"(?m)^irm \S+ \| iex \S")


class FirstInstallWalkthrough(unittest.TestCase):
    """First install showed a Batocera run of 12893 files with no omission
    line and said any other ending meant work left undone, while every
    Batocera run printed 399 files not installed. Its disk sizes (Batocera
    4.0 GB) contradicted its own example (8.6 GB), and its no-platform case
    said a piped command cannot ask, where install.sh hands it the terminal
    and the installer shows a menu. The annotated run now lives in the
    installer page, under Reading a run: First install keeps the steps."""

    def setUp(self):
        self.text = _page("first-install.md")
        self.run = _page("installer.md")

    def test_the_stop_keys_are_the_ones_the_screen_names(self):
        """The page said "B or Ctrl+C stops it" for a computer, whose screen
        says Esc or Ctrl-C, and where the b key does nothing."""
        import install

        section = _section(self.text, "4. Wait")
        computer = install.TUI_ROUTES["keys"].stop[0].replace("Ctrl-C", "Ctrl+C")
        self.assertIn(f"{computer} stops", section)
        self.assertIn(f"{install.TUI_ROUTES['gptokeyb'].stop[0]} on a handheld", section)

    def test_no_hand_kept_size_before_the_run(self):
        import install

        section = _section(self.run, "Before the run")
        # The confirmation threshold is a constant of the installer, not a pack size.
        self.assertEqual(install.CONFIRM_FROM_BYTES, 1024 ** 3)
        self.assertIn("reaches 1 GB", section)
        self.assertNotRegex(section.replace("reaches 1 GB", ""), r"\d+(\.\d+)? ?[KMG]B\b")

    def test_the_run_is_one_run_of_the_manifest(self):
        """The counts are printed by the generator, so they are not retyped
        here: what is checked is that the five samples are one run."""
        import install

        # First install names the three endings the full screen shows as
        # its title, and no count: a figure from one setup read as the size
        # of every install.
        source = (ROOT / "install.py").read_text(encoding="utf-8")
        for ending in ("Done", "Finished with errors", "Nothing installed"):
            with self.subTest(ending=ending):
                self.assertIn(f"**{ending}**", _section(self.text, "5. Read the result"))
                self.assertRegex(source, rf'return \(?"{ending}",')
        self.assertNotRegex(self.text, r"\d+ (in place|missing|files installed)")
        self.assertIn(f"  {install.EVERYTHING_IN_PLACE}", self.text)
        step3 = _generated(self.run, "run-index")
        count = re.search(r"\n  (\d+) files \([\d.]+ [KMG]B\)", step3).group(1)
        self.assertIn(f"0 in place, {count} missing", step3)
        # The data trees are fetched after the files, from their archives:
        # the download line counts the files alone.
        trees = re.search(r" and (\d+) data files", step3)
        downloaded = int(count) - (int(trees.group(1)) if trees else 0)
        self.assertRegex(_generated(self.run, "run-download"),
                         rf"Downloading {downloaded} files \([\d.]+ [KMG]B\)")
        step4 = _generated(self.run, "run-end")
        self.assertIn(f"Done. {count} files installed", step4)
        self.assertIn(f"{count} in place, 0 missing", _generated(self.run, "run-check"))
        manifest = json.loads((ROOT / "install" / "batocera.json").read_text(encoding="utf-8"))
        omitted = manifest.get("omitted_files") or []
        self.assertEqual("Not installable:" in step3, bool(omitted))
        # The prose under the end of the run names both lines a required
        # omission can take, whichever this list prints.
        section = _section(self.run, "The end of the run")
        for words in ("Not available here", "Needed to start an emulator"):
            self.assertIn(f"`{words}`", section)
        needed = [entry for entry in omitted if entry.get("required")]
        if any(entry.get("category") == install.GAME_DATA for entry in needed):
            self.assertIn("Not available here:", step4)
        if any(entry.get("category") != install.GAME_DATA for entry in needed):
            self.assertIn("Needed to start an emulator", step4)

    def test_nothing_found_reads_like_the_installer(self):
        # The one-liner hands the terminal to the installer, which opens the
        # full screen: its first screen says the heading and offers the row.
        import install

        self.assertIn('"$INSTALLER" "$@" </dev/tty', (ROOT / "install.sh").read_text(encoding="utf-8"))
        state = install.TuiState()
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("Nothing was found here.", screen)
        section = _section(self.text, "Nothing was found here.")
        self.assertIn(f"**{install.tui_rows(state)[-1].label}**", section)
        self.assertNotIn("cannot stop and ask", section)


class RetroArchWindowsSystemFolder(unittest.TestCase):
    """Getting started gave %APPDATA%\\RetroArch\\system for the Windows
    installer. RetroArch's default is `:\\system`, the folder of
    retroarch.exe (platform_win32.c). %APPDATA% is where a retroarch.cfg
    can live, and install.py reads it there. The RetroArch page of the site
    states the folder now, from the guide data."""

    def test_page_and_installer_agree(self):
        import install

        source = inspect.getsource(install)
        self.assertIn('ra_dir or exe_dir / "system"', source)
        self.assertTrue(str(install._os_default_dests("windows")["retroarch"]).replace("\\", "/").endswith("/system"))
        from sitegen.guidedata import platform_guides

        guide = platform_guides()["retroarch"]
        section = "\n".join([*(path for _label, path in guide.folders), *guide.notes])
        self.assertNotIn("%APPDATA%\\RetroArch\\system", section)
        self.assertIn("`system\\` next to `retroarch.exe`", section)

    def test_the_macos_folder_is_the_installers(self):
        """The site gave Application Support/RetroArch/system for macOS. A
        RetroArch left at its defaults reads ~/Documents/RetroArch/system
        (platform_darwin.m), Application Support only for a portable or
        Steam build, and install.py looks there in that order."""
        import install
        from sitegen.guidedata import platform_guides

        source = inspect.getsource(install._macos_retroarch_base)
        self.assertIn('Path.home() / "Documents" / "RetroArch"', source)
        folders = dict(platform_guides()["retroarch"].folders)
        self.assertEqual(folders["macOS"], "`~/Documents/RetroArch/system/`")


# The pages that describe the installer, and the ones that cite its options.
INSTALLER_PAGES = ("installer.md", "first-install.md", "troubleshooting.md", "faq.md")

OPTION_PAGES = INSTALLER_PAGES + ("advanced-usage.md", "technical-faq.md")

INSTALLER_SOURCES = ("install.py", "install.sh", "install.ps1")

OPTION = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]+)")

SCRIPT = re.compile(r"(?<![\w/.-])(?:scripts/)?([a-z_]+\.(?:py|sh))\b")

# Programs whose own options a page quotes: what follows them is theirs.
FOREIGN_COMMANDS = ("curl --", "xcode-select", "wget", "git ", "npm ", "gh ", "uvx ", "sha256sum")

# Variables the standard library reads for the installer, which install.py
# never spells: NO_PROXY reaches urllib through getproxies().
STDLIB_VARIABLES = {"NO_PROXY": "urllib.request"}

# Messages a page quotes from another program, with the program.
FOREIGN_MESSAGES = {"A positional parameter cannot be found": "PowerShell, on `irm ... | iex --x`"}

# Words the operating system hands the installer to print (strerror).
OS_WORDS = ("Permission denied",)


def _prose(text: str) -> str:
    """A page without its fenced blocks and comments."""
    return re.sub(r"<!--.*?-->", "", FENCED.sub("", text), flags=re.S)


def _parser_options() -> set[str]:
    import install

    return {name for action in install.build_parser()._actions
            for name in action.option_strings if name.startswith("--")}


def _script_options(name: str) -> set[str]:
    """The options a build script spells, in its file or a module beside it
    that it imports, and the shared ones its parser adds through core.cli."""
    path = next((p for p in (ROOT / "scripts" / name, ROOT / name) if p.is_file()), None)
    if path is None:
        return set()
    own = text = path.read_text(encoding="utf-8")
    for module in re.findall(r"(?m)^(?:from|import) (\w+)", text):
        beside = path.parent / f"{module}.py"
        if beside.is_file() and beside != path:
            text += beside.read_text(encoding="utf-8")
    if path.suffix == ".sh":
        return set(OPTION.findall(text))
    spelled = set(re.findall(r"""["'](--[a-z][a-z0-9-]+)["'=]""", text)) | {"--help"}
    return spelled | declared_options(own) if path.suffix == ".py" else spelled


def _owner(command: str) -> str | None:
    """The program a command line runs: install.py for the one-liners."""
    if re.search(r"install\.py|\| *sh\b|scriptblock|install\.(?:sh|ps1)\b", command):
        return "install.py"
    named = SCRIPT.search(command)
    return named.group(1) if named else None


def stale_options(text: str, default: str | None) -> list[str]:
    """Options a page cites that the program it names does not have.

    A command line answers for the program it runs. An option in prose
    answers for the scripts its paragraph names, for default (the
    installer, on its own pages) and for the scripts the page runs."""
    known = {"install.py": _parser_options()}

    def has(program: str, option: str) -> bool:
        if program not in known:
            known[program] = _script_options(program)
        return option in known[program]

    commands = []
    for block in FENCED.findall(text):
        commands += [line for line in block.splitlines()[1:-1] if not line.lstrip().startswith("#")]
    page_scripts = {owner for command in commands if (owner := _owner(command))}
    stale: list[str] = []
    for line in commands:
        for part in re.split(r"\s+&&\s+|;\s+|\|\s+(?!sh\b)", line):
            if not part or part.lstrip().startswith(FOREIGN_COMMANDS):
                continue
            program = _owner(part) or default
            stale.extend(
                f"{option} ({program}): {part.strip()}"
                for option in OPTION.findall(part)
                if program is None or not has(program, option)
            )
    for paragraph in re.split(r"\n\s*\n", _prose(text)):
        named = {m.group(1) for m in SCRIPT.finditer(paragraph)} - {"install.sh", "install.ps1"}
        owners = named | page_scripts | ({default} if default else set())
        for span in re.findall(r"`([^`]+)`", paragraph.replace("\n", " ")):
            if span.startswith(FOREIGN_COMMANDS):
                continue
            own = _owner(span)
            candidates = {own} if own else owners
            stale.extend(
                f"{option} ({', '.join(sorted(candidates))}): {span}"
                for option in OPTION.findall(span)
                if not any(has(program, option) for program in candidates)
            )
    return stale


def stale_variables(text: str) -> list[str]:
    """Environment variables a page names that neither the installer nor
    its bootstraps and launchers read."""
    sources = "".join((ROOT / name).read_text(encoding="utf-8") for name in INSTALLER_SOURCES)
    sources += "".join(path.read_text(encoding="utf-8", errors="replace")
                       for path in sorted((ROOT / "ports").rglob("*")) if path.is_file())
    found: set[str] = set()
    for span in re.findall(r"`([^`]+)`", _prose(text)):
        found |= set(re.findall(r"(?<![\w$%.-])([A-Z][A-Z0-9]*_[A-Z0-9_]+|NO_COLOR|TERM|ACCESSIBLE)"
                                r"(?![\w.(])", span))
    return sorted(name for name in found if name not in sources and name not in STDLIB_VARIABLES)


def _literals() -> str:
    """Every string the installer and its bootstraps print, a placeholder
    (\\x01) where an f-string or the shell inserts a value, joined by \\x00."""
    texts = []
    for node in ast.walk(ast.parse((ROOT / "install.py").read_text(encoding="utf-8"))):
        if isinstance(node, ast.JoinedStr):
            texts.append("".join(str(value.value) if isinstance(value, ast.Constant) else "\x01"
                                 for value in node.values))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            texts.append(node.value)
    for name in ("install.sh", "install.ps1"):
        for match in re.finditer(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'',
                                 (ROOT / name).read_text(encoding="utf-8")):
            quoted = match.group(1) if match.group(1) is not None else match.group(2)
            texts.append(re.sub(r"\$\{[^}]*\}|\$\([^)]*\)|\$\w+", "\x01", quoted))
    return "\x00".join(re.sub(r"\s+", " ", text) for text in texts)


# A word a message fills in: a number, a path, a name in capitals, an option.
VALUE = re.compile(r"^(?:\S*[\d/\\~<>{}=]\S*|--?[\w-]+\S*|\S*[A-Z]{2,}\S*|\.\.\.|"
                   r"\S*\.\w{2,4}[,.:;)]?|[A-Z][a-z]+[A-Z]\S*|\(\S*)$")

# A code span that is a command, a path or a shape, not a message.
NOT_A_MESSAGE = re.compile(r"^(?:\{|-|\.|/|~|<|\$|%|python|py |curl|irm|uvx |pipx |pip |sh |pkg |sudo|ls |"
                           r"xcode|winget|termux|install\.py|scripts/|generate_|&\()")


def unprinted_messages(text: str, corpus: str) -> list[str]:
    """Code spans that read as installer messages and that no string of
    the installer prints.

    The values a message fills in (counts, paths, names) are free. Between
    them, the words must be printed together by one string, each pair of
    them at least, or beside a value that string inserts."""

    def pair_printed(first: str, second: str) -> bool:
        pair = f"{first} {second}".rstrip(".,:;")
        forms = {pair, re.sub(r"s\b", "", pair), re.sub(r"s( |$)", r"\1", pair),
                 f"{first} \x01", f"\x01 {second}".rstrip(".,:;")}
        return any(form in corpus for form in forms)

    stale = []
    for span in sorted({re.sub(r"\s+", " ", s) for s in re.findall(r"`([^`]+)`", _prose(text))}):
        if NOT_A_MESSAGE.match(span) or len(span.split()) < 3 or span in FOREIGN_MESSAGES:
            continue
        words = span
        for given in OS_WORDS:
            words = words.replace(given, "1")
        run: list[str] = []
        for word in [*words.split(" "), "1"]:
            if word and not VALUE.match(word):
                run.append(word)
                continue
            joined = " ".join(run)
            if len(run) > 1 and joined.rstrip(".,:;") not in corpus and not all(
                    pair_printed(a, b) for a, b in zip(run, run[1:])):
                stale.append(f"{span!r}: {joined!r}")
            run = []
    return stale


def unserved_one_liners(page: str, text: str) -> list[str]:
    """One-line commands whose address the site does not serve. The raw
    address of the repository stays as the fallback of the One line
    section, and must name a bootstrap the repository holds."""
    from sitegen import bootstrap as sitebootstrap
    from sitegen.guidedata import install_base

    served = {f"{install_base()}/{name}" for name in sitebootstrap.SOURCES}
    fallback = _section(text, "One line") if page == "installer.md" else ""
    stale = []
    for line in text.splitlines():
        if not re.search(r"\|\s*(?:sh|iex)\b|\\$|scriptblock\]::Create", line):
            continue
        for url in re.findall(r"https?://[^\s)`'\"]+", line):
            if url in served:
                continue
            raw = re.fullmatch(rf"{re.escape(sitebootstrap.REPO_RAW)}/main/(install\.(?:sh|ps1))", url)
            if raw and line in fallback and (ROOT / raw.group(1)).is_file():
                continue
            stale.append(f"{url}: {line.strip()}")
    return stale


class InstallerPagesFollowTheCode(unittest.TestCase):
    """The installer page described an installer that had moved on, and
    nothing failed. Options, variables, messages and addresses are words
    the code owns, so each page is read against the code here."""

    def test_every_option_is_the_programs(self):
        for name in OPTION_PAGES:
            default = "install.py" if name in INSTALLER_PAGES else None
            with self.subTest(page=name):
                self.assertEqual(stale_options(_page(name), default), [])

    def test_an_option_the_program_lacks_fails(self):
        old = "Add `--resume` to carry on.\n\n```bash\npython install.py --keep-going\n```\n"
        self.assertEqual(len(stale_options(old, "install.py")), 2)
        self.assertEqual(stale_options("`curl --tlsv1.2` and `--check`.\n", "install.py"), [])
        self.assertEqual(stale_options("```bash\npython scripts/verify.py --all\n```\n", None), [])
        self.assertEqual(len(stale_options("```bash\npython scripts/verify.py --sideways\n```\n",
                                           None)), 1)

    def test_every_variable_is_read(self):
        import urllib.request

        for variable in STDLIB_VARIABLES:
            self.assertIn(variable.lower(), inspect.getsource(urllib.request.proxy_bypass_environment))
        for name in INSTALLER_PAGES:
            with self.subTest(page=name):
                self.assertEqual(stale_variables(_page(name)), [])

    def test_a_variable_nothing_reads_fails(self):
        self.assertEqual(stale_variables("Set `RETROBIOS_MIRROR` to another host.\n"),
                         ["RETROBIOS_MIRROR"])

    def test_every_quoted_message_is_printed(self):
        corpus = _literals()
        for name in INSTALLER_PAGES:
            with self.subTest(page=name):
                self.assertEqual(unprinted_messages(_page(name), corpus), [])

    def test_a_message_the_installer_does_not_print_fails(self):
        corpus = _literals()
        self.assertEqual(unprinted_messages("It ends `Every file on the list is in place.` here.\n", corpus), [])
        self.assertEqual(len(unprinted_messages("It says `All BIOS files are present.`\n", corpus)), 1)
        self.assertEqual(unprinted_messages(
            "`E:\\ holds 38 of these files: a run without --check copies them.`\n", corpus), [])

    def test_every_one_liner_is_served(self):
        for name in OPTION_PAGES:
            with self.subTest(page=name):
                self.assertEqual(unserved_one_liners(name, _page(name)), [])

    def test_a_one_liner_the_site_does_not_serve_fails(self):
        """Before the site served `i`, every page gave the raw address."""
        old = ("## One line\n\nIntro.\n\n## Passing options\n\n```bash\ncurl -fsSL "
               "https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh \\\n"
               "  | sh -s -- --platform retroarch\n```\n\n"
               "```bash\ncurl -fsSL https://abdess.github.io/retrobios/install | sh\n```\n")
        self.assertEqual(len(unserved_one_liners("installer.md", old)), 2)


class InstallerVariablesAreDocumented(unittest.TestCase):
    """RETROBIOS_CACHE moved a cache that --for-games writes, even under
    --dry-run, and no page named it or the folder it defaults to."""

    # Set by the full-screen interface for the runs it starts, never by a user.
    INTERNAL = {"RETROBIOS_TUI_LIST", "RETROBIOS_TUI_RECORDED"}

    def test_every_variable_install_py_reads_is_in_the_table(self):
        source = (ROOT / "install.py").read_text(encoding="utf-8")
        page = (WIKI / "installer.md").read_text(encoding="utf-8")
        table = page[page.index("## Environment overrides"):]
        table = table[:table.index("\n## ", 1)]
        for name in sorted(set(re.findall(r'"(RETROBIOS_[A-Z_]+)"', source)) - self.INTERNAL):
            with self.subTest(variable=name):
                self.assertIn(f"`{name}`", table)

    def test_the_faq_names_the_cache(self):
        faq = (WIKI / "faq.md").read_text(encoding="utf-8")
        section = faq[faq.index("## Is the command safe?"):]
        self.assertIn("cache", section[:section.index("\n## ", 1)])


class TheInstallerSamplesTravelWithTheManifests(unittest.TestCase):
    """A manifest refresh (c624a820f) went out without the run samples of
    wiki/installer.md, which count what the manifests hold, and CI turned
    red. The rule lived in no page, and the nightly's commit rules had no
    place for the samples the gate's pipeline rewrites."""

    def test_the_pages_and_the_nightly_carry_them(self):
        from core.generated import matches_any
        from unattended import jobs

        guide = (WIKI / "testing-guide.md").read_text(encoding="utf-8")
        for name in ("wiki/installer.md", "derivable.json", "generate_installer_doc.py"):
            self.assertIn(name, guide)
        tools = (WIKI / "tools.md").read_text(encoding="utf-8")
        manifests = tools.index("--all --manifest --output-dir install/")
        self.assertIn("generate_installer_doc.py", tools[manifests:manifests + 300])
        nightly = jobs.load_jobs()["nightly"]
        patterns = [p for rule in nightly.commits for p in rule.paths]
        for path in ("wiki/installer.md", "derivable.json", "install/retroarch.json"):
            with self.subTest(path=path):
                self.assertTrue(matches_any(path, patterns))


class BuildYourOwnPackSaysWhatTheCloneCosts(unittest.TestCase):
    """The README sent a user after a minimal pack to "Clone the repo", with no
    command and no size, and the clone runs to several gigabytes."""

    def test_readme_gives_the_clone_command_and_its_size(self):
        from sitegen import readme as sitegen_readme

        db = json.loads((ROOT / "database.json").read_text(encoding="utf-8"))
        line = sitegen_readme.clone_line(db)
        self.assertIn("git clone --depth 1", line)
        self.assertRegex(line, r"over \d+(\.\d)? GB")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        section = readme[readme.index("<summary><strong>For developers"):readme.index("</details>")]
        self.assertIn("git clone --depth 1", section)

    def test_advanced_usage_names_the_shallow_clone(self):
        self.assertIn("--depth 1", _page("advanced-usage.md").split("## Custom packs")[0])


if __name__ == "__main__":
    unittest.main()
