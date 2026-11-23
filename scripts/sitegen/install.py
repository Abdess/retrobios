"""Install blocks and commands for an emulator, a platform or a console."""

from __future__ import annotations

import functools
import html
import json
import re
import shlex
from collections import Counter
from pathlib import Path

from core.text import series
from model import siteinputs
from model.collection import profiles_in
from sitegen.guidedata import platform_guides, terminals, install_command
from model.platforms import load_platform_config
from model.registry import list_release_pack_platforms
from model.profiles import reads_own_files
from resolve.layout import data_root_place, runs_standalone
from resolve.standalone import standalone_set
from resolve.validation import installed_everywhere, installed_with_emulator
from sitegen import markup
from installer_build.module import installer_module
from sitegen.fields import search_excluded
from sitegen.guides import fence, platform_args, terminal_tabs
from sitegen.render import code_span, escape_tags
from sitegen.sources import source_ref_markdown


def has_release_pack(platform_name: str) -> bool:
    """Whether a release publishes a ZIP for the platform (`release_pack`)."""
    return platform_name in release_pack_platforms()


def release_pack_platforms() -> frozenset[str]:
    return _release_packs_in(str(siteinputs.current().platforms))


@functools.cache
def _release_packs_in(platforms_dir: str) -> frozenset[str]:
    return frozenset(list_release_pack_platforms(platforms_dir))


def manifest_systems(platform: str) -> frozenset[str]:
    """The system ids a platform's install manifest records: --system
    refuses any other."""
    return _manifest_systems_in(str(siteinputs.manifests_dir()), platform)


@functools.cache
def _manifest_systems_in(manifests_dir: str, platform: str) -> frozenset[str]:
    manifest = Path(manifests_dir) / f"{platform}.json"
    if not manifest.is_file():
        return frozenset()
    document = json.loads(manifest.read_text(encoding="utf-8"))
    return frozenset(
        str(system)
        for entry in (document.get("files") or []) + (document.get("omitted_files") or [])
        for system in entry.get("systems") or []
    )


def display_name(config: dict, name: str) -> str:
    """The `platform:` a loaded platform config writes, else its key."""
    return str(config.get("platform") or name)


def platform_display(name: str, platforms_dir: str | None = None) -> str:
    """A setup's name as its platform file writes it: Batocera, not batocera."""
    return _platform_display_in(platforms_dir or str(siteinputs.current().platforms), name)


@functools.cache
def _platform_display_in(platforms_dir: str, name: str) -> str:
    try:
        config = load_platform_config(name, platforms_dir)
    except FileNotFoundError:
        config = {}
    return display_name(config, name)


def comes_with_app(f: dict) -> bool:
    """The emulator installs the file in the build the entry describes, on every setup.

    The rule the gap report and the wanted list read (``installed_everywhere``),
    for a page that names no setup. An entry a platform package leaves out
    (``not_bundled_on``: Batocera's hcl installs the binary alone) is a file
    that setup's readers get, and the manifests serve it there. An entry
    narrowed by ``mode`` is that build's alone: the other build reads its
    own entry, or nothing.
    """
    return installed_everywhere(f)


def install_commands(args: str = "", indent: str = "",
                     oses: tuple[str, ...] | None = None) -> list[str]:
    """The same install for each place a user runs it: one generator for the
    download page and the platform, system and emulator pages, so none of
    them loses the Android or Windows form.

    ``oses`` names the terminals (keys of terminals()) the command runs in,
    written as the synced OS tabs: MAME4droid runs on Android only, and its
    page offered a PowerShell command. None keeps the three blocks.
    """
    if oses is not None:
        return terminal_tabs(oses, dict.fromkeys(oses, args), indent)
    lines = []
    for label, shell in (
        ("Linux, macOS, Steam Deck:", "sh"),
        ("Windows (PowerShell):", "powershell"),
        ("Android (Termux, the command installs Python and asks for storage access):", "sh"),
    ):
        lines += [f"{indent}{label}", "", *fence(shell, install_command(shell, args), indent), ""]
    return lines


def _published_emulator_names() -> dict[str, dict[str, str]]:
    """Per published manifest, every name `--emulator` accepts there and the
    profile it stands for, as `install.py --list-emulators` prints them."""
    return _published_emulator_names_in(str(siteinputs.manifests_dir()))


@functools.cache
def _published_emulator_names_in(manifests_dir: str) -> dict[str, dict[str, str]]:
    installer = installer_module()
    names: dict[str, dict[str, str]] = {}
    for path in sorted(Path(manifests_dir).glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        names[path.stem] = installer.emulator_names(
            manifest, manifest.get("files") or [], manifest.get("omitted_files") or [])
    return names


# Where a setup's command runs, in the order the tabs show them.
_COMMAND_TERMINALS = ("windows", "macos", "linux", "steamdeck", "android", "device")

# The terminals an app's data_root key covers: the Deck runs the Linux build.
_DATA_ROOT_TERMINALS = {
    "windows": ("windows",), "macos": ("macos",), "linux": ("linux", "steamdeck"),
    "android": ("android",), "ios": (),
}


def emulator_install_route(name: str, profile: dict) -> tuple[str, list[str], tuple[str, ...]]:
    """The name `--emulator` takes for this profile, the setups the command
    fills, and the terminals it runs in, or ("", [], ()) when none works.

    A name works where a published manifest maps it to this profile: 215
    pages printed a command every manifest refused. A setup counts when the
    installer finds it without `--dest`. A standalone app is reached only
    through a setup that launches it as an app (its standalone_cores), on
    the systems both run on: RetroArch's list names AetherSX2, and the
    command filled RetroArch's system folder, which the app never reads.
    """
    if not reads_own_files(profile):
        return "", [], ()
    files = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    standalone = profile.get("type") == "standalone"
    accepted: dict[str, set[str]] = {}
    for platform, names in _published_emulator_names().items():
        if platform not in platform_guides():
            continue
        # Decided per setup, as the manifest decides it: Batocera's hcl
        # package leaves out the 667 files every other setup's install brings.
        if all(installed_with_emulator(f, platform) for f in files):
            continue
        if standalone and not runs_standalone(name, profile, _standalone_cores(platform)):
            continue
        if any("--dest" in args for args in platform_args(platform, platform_guides()[platform]).values()):
            continue
        own = {n for n, target in names.items() if target == name}
        if own:
            accepted[platform] = own
    if not accepted:
        return "", [], ()
    # The profile's own name where a setup takes it, else the alias most
    # setups take: the one command must work on every setup it names.
    candidates = set().union(*accepted.values())
    command = min(candidates, key=lambda n: (
        -sum(n in own for own in accepted.values()), n != name, n))
    guides = platform_guides()
    order = list(guides)
    setups = sorted((p for p, own in accepted.items() if command in own), key=order.index)
    runs_in = {key for setup in setups for key in guides[setup].run}
    if isinstance(profile.get("data_root"), dict):
        # Only the systems the program is built for (Cemu has no Android
        # build). A device setup runs it itself: its terminal stays.
        runs_in &= {"device", *(t for key in profile["data_root"]
                                   for t in _DATA_ROOT_TERMINALS.get(key, ()))}
    oses = tuple(key for key in _COMMAND_TERMINALS if key in runs_in)
    if not oses:
        return "", [], ()
    return command, setups, oses


def _standalone_cores(platform: str) -> frozenset[str]:
    """The emulators a setup launches as apps, by its platform file."""
    inputs = siteinputs.current()
    return _standalone_cores_in(str(inputs.platforms), str(inputs.emulators), platform)


@functools.cache
def _standalone_cores_in(platforms_dir: str, emulators_dir: str, platform: str) -> frozenset[str]:
    config = load_platform_config(platform, platforms_dir)
    return frozenset(standalone_set(config, profiles_in(emulators_dir, skip_aliases=True)))


def install_block(name: str, profile: dict) -> list[str]:
    """One command that installs this emulator's files where it reads them.

    The installer finds the setup and its BIOS folder, then keeps what this
    emulator reads there: its own files and the setup's files of the
    systems it runs. Written only where a published manifest takes the
    name, in the terminals of the setups that run it. `--emulator` turns off
    the pass that fills a lone app's folders (install.py, `narrowing` in
    main), so an app on its own is named with the setup that serves it.
    """
    command, setups, oses = emulator_install_route(name, profile)
    if not command:
        return []
    emu = str(profile.get("emulator") or name)
    shown = [platform_display(setup) for setup in setups]
    if profile.get("type") == "standalone":
        lead = (f"With {series(shown, 'or')}: the installer finds {series(shown, 'or')} and its "
                f"BIOS folder, then downloads only the files {emu} reads there and checks "
                "each one.")
    else:
        lead = ("The installer finds the setup and its BIOS folder, then downloads "
                "only the files this emulator reads there and checks each one.")
        if profile.get("type") == "standalone + libretro":
            # The command fills a setup, never the app's own folder.
            where = (series(shown, 'or') if len(shown) <= 3
                     else f"{shown[0]}, {shown[1]} or another setup")
            lead = f"For {emu} inside {where}. {lead}"
    return search_excluded(markup.details("tip", "Install this emulator's files", [
        lead,
        "",
        *install_commands(f"--emulator {command}", oses=oses),
    ]))


def standalone_place(profile: dict, entry: dict, key: str = "") -> str:
    """Where under the data folder the app reads this entry, or "".

    The place the installer copies the file to (resolve.layout.data_root_place),
    and nothing for an entry the app ships.
    """
    if not isinstance(entry, dict) or comes_with_app(entry):
        return ""
    return data_root_place(profile, entry, key)


OS_LABELS = {"windows": "Windows", "macos": "macOS", "linux": "Linux",
              "android": "Android", "ios": "iOS"}


def under_root(root: str, folder: str) -> str:
    """``root`` with ``folder`` below it, as code: each alternative of
    "$XDG_CONFIG_HOME/x, else ~/.config/x", and a root written in words
    ("the folder picked in the setup wizard") kept as words."""
    folder = folder.strip("/")
    shown = []
    for alternative in root.split(", else "):
        alternative = alternative.strip()
        if " " in alternative and "/" not in alternative and not alternative.startswith("<"):
            shown.append(f"{code_span(folder + '/')} in {escape_tags(alternative)}"
                         if folder else escape_tags(alternative))
            continue
        joined = alternative.rstrip("/") + (f"/{folder}" if folder else "") + "/"
        shown.append(code_span(joined))
    return ", else ".join(shown)


def _data_root_folder(profile: dict, key: str, entries: list[dict]) -> str:
    """The one folder under the root that every entry the app reads sits
    in, or "": VICE places 3 of its 322 files in DRIVES/, and naming that
    folder would send the other 319 there."""
    folders = set()
    for f in entries:
        mode = f.get("mode")
        if mode == "libretro" or comes_with_app(f):
            continue
        place = standalone_place(profile, f, key)
        if not place:
            return ""
        folders.add(place.rpartition("/")[0])
    return folders.pop() if len(folders) == 1 else ""


def data_folder_block(profile: dict, entries: list[dict] | None = None) -> list[str]:
    """The app's data folder, one tab per system it runs on, each with the
    code that names it and its note: 61 profiles cite it and no page showed
    it. ``entries`` are the files the folder is for: when they all sit in
    one folder below the root, the tab names that folder."""
    roots = profile.get("data_root") or {}
    if not isinstance(roots, dict) or not roots:
        return []
    if entries is None:
        entries = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    items = []
    for key in ("windows", "macos", "linux", "android", "ios"):
        root = roots.get(key)
        if not isinstance(root, dict) or not root.get("path"):
            continue
        path = str(root["path"])
        line = under_root(path, _data_root_folder(profile, key, entries))
        if key == "android" and path.startswith("Android/data/"):
            line += ", on the internal storage."
        body = [line]
        note = " ".join(str(root.get("note") or "").split()).rstrip(".")
        if note:
            # "the folder" reads as a sentence, "portable.ini" keeps its case.
            first = note.split(" ", 1)[0]
            if first.isalpha() and first.islower():
                note = note[:1].upper() + note[1:]
            body += ["", escape_tags(note) + "."]
        body += ["", f"Source: {source_ref_markdown(profile, str(root['source_ref']))}"]
        items.append((OS_LABELS[key], body))
    if len(items) == 1:
        label, body = items[0]
        return [f"On {label}: {body[0]}", *body[1:], ""]
    return markup.tabs(items)


def data_root_words(text: str, href: str = "#data-folder") -> str:
    """Prose that names the field data_root, linked to the folder it holds:
    ten pages told readers "given in data_root"."""
    return re.sub(r"\bdata_root\b", f"[the data folder]({href})", text)


def platform_install_block(name: str, display: str, on_card: bool = False) -> list[str]:
    """The platform's pack, installed file by file: what the ZIP holds, with
    resume, verification and only what is missing.

    ``on_card``: the files go on the frontend's SD card, installed from the
    computer it is mounted on, whose root is named.
    """
    if on_card:
        return markup.details("tip", "Install with one command", [
            f"With the {display} SD card mounted, the installer downloads the files "
            "of the pack that are missing or differ from it into `Bios/<TAG>/` on "
            "the card, checks each one, and resumes where it stopped. `--dest` "
            "names the card's root.",
            "",
            "Linux, macOS:",
            "",
            *fence("sh", install_command("sh", f"--platform {name} --dest /path/to/card")),
            "",
            "Windows (PowerShell, E: being the card):",
            "",
            *fence("powershell", install_command("powershell", f"--platform {name} --dest E:\\")),
        ], opened=True)
    return markup.details("tip", "Install with one command", [
        f"The installer downloads the files of the {display} pack that are "
        "missing or differ from it, checks each one, and resumes where it "
        "stopped. Add `--system` with the ids of the systems overview below "
        "to install fewer systems.",
        "",
        *install_commands(f"--platform {name}"),
    ], opened=True)


def _ps_quote(value: str) -> str:
    """A PowerShell argument: bare when plain, single-quoted otherwise."""
    return value if re.fullmatch(r"[\w.+-]+", value) else "'" + value.replace("'", "''") + "'"


# The OS tabs of a system's install box: labels the site's other command
# tabs use, so the reader's choice carries from page to page.
INSTALL_PICKER_OSES = ("windows", "macos", "linux", "steamdeck")


def _install_args(platform: str, system: str, shell: str) -> str:
    quoted = _ps_quote(system) if shell == "powershell" else shlex.quote(system)
    return f"--platform {platform} --system {quoted}"


def _default_setup(declared: list[tuple[str, str]]) -> tuple[str, str]:
    """The setup an install box shows before the reader picks one.

    The first in alphabetical order was AmberELEC on 17 system pages, a
    handheld system under a Windows tab. The box shows the setup whose
    command runs under the most of its tabs (the guide's `run`), then on the
    most systems overall, then one the release publishes a ZIP for.
    """
    def reach(pair: tuple[str, str]) -> tuple[int, int, bool]:
        guide = platform_guides().get(pair[0])
        runs = guide.run if guide else ()
        return (len(set(runs) & set(INSTALL_PICKER_OSES)), len(runs), has_release_pack(pair[0]))

    return max(declared, key=reach)


def _install_picker(declared: list[tuple[str, str]]) -> list[str]:
    """One command, for the setup the reader picks, under the OS tabs.

    Every setup's command for a console was written out, twice: 12 long
    lines for the PSP, about 360 page elements once highlighted. The
    picker shows one and the script (site.ts) rewrites it for the setup
    chosen, remembered from page to page. Without the script the picker
    stays hidden and the plain list of every command shows, open.
    """
    def attribute(text: str) -> str:
        # Quotes kept as written: a system id quoted for the shell ('Neo Geo').
        return html.escape(text, quote=False).replace('"', "&quot;")

    names = Counter(platform for platform, _system in declared)
    lead = _default_setup(declared)
    options = "".join(
        f'<option value="{attribute(platform)}"'
        + (" selected" if (platform, system) == lead else "")
        + f' data-sh="{attribute(_install_args(platform, system, "sh"))}" '
        f'data-ps="{attribute(_install_args(platform, system, "powershell"))}">'
        + html.escape(platform_display(platform) + (f" ({system})" if names[platform] > 1 else ""),
                      quote=False)
        + "</option>"
        for platform, system in declared)
    args = {key: _install_args(*lead, terminals()[key][2]) for key in INSTALL_PICKER_OSES}
    return [
        "Each platform names the system its own way.",
        "",
        '<div class="rb-install" data-rb-install="" hidden>',
        "",
        f'<label class="rb-install-setup">Setup <select>{options}</select></label>',
        "",
        *terminal_tabs(INSTALL_PICKER_OSES, args, steps=False),
        "",
        "</div>",
        "",
        # Each command as inline code, no highlighting: the list is the
        # fallback and the reference, and highlighted it was most of the
        # box's elements.
        '<details class="rb-install-all" open>',
        "<summary>Every setup's command</summary>",
        "",
        *_command_list("Terminal (Linux, macOS, Steam Deck):", declared, "sh"),
        *_command_list("PowerShell (Windows):", declared, "powershell"),
        "</details>",
    ]


def _command_list(label: str, declared: list[tuple[str, str]], shell: str) -> list[str]:
    """Every setup's command for one shell, a line each, with a copy button.

    Inline HTML code, so no break element is added at each slash. A break
    point follows the URL's scheme: the Markdown around the code made the
    bare URL a link inside the command, and a scheme with nothing after it
    is no link. The break adds no character to a copy."""
    def command(platform: str, system: str) -> str:
        text = html.escape(install_command(shell, _install_args(platform, system, shell)), quote=False)
        return text.replace("://", "://<wbr>")

    # One HTML line: the glossary leaves HTML alone, and it marked a word
    # inside a command.
    names = Counter(platform for platform, _system in declared)
    items = "".join(
        f"<li>{html.escape(platform_display(platform), quote=False)}"
        + (f" ({html.escape(system, quote=False)})" if names[platform] > 1 else "")
        + f': <code data-copy="">{command(platform, system)}</code></li>'
        for platform, system in declared)
    return [label, "", f"<ul>{items}</ul>", ""]


def console_install_block(console: str, declared: list[tuple[str, str]]) -> list[str]:
    """Each platform's command for one console, by the system id it gives it,
    for a terminal and for PowerShell, each under its setup's name: RetroBat
    had two lines and nothing said which was for the Neo Geo."""
    if not declared:
        return []
    sh = [line for platform, system in declared for line in (
        f"# {platform_display(platform)}",
        install_command("sh", f"--platform {platform} --system {shlex.quote(system)}"))]
    ps = [line for platform, system in declared for line in (
        f"# {platform_display(platform)}",
        install_command("powershell", f"--platform {platform} --system {_ps_quote(system)}"))]
    # The name last: "Install the Atari System 1 files" read as a count. A
    # label naming files already reads "Install these files": "Install
    # the files of Other arcade files".
    summary = ("Install these files" if console.casefold().endswith(" files")
               else f"Install the files of {console}")
    if markup.starlight() and len(declared) > 1:
        return search_excluded(markup.details("tip", summary, _install_picker(declared)))
    return search_excluded(markup.details("tip", summary, [
        "Each platform names the system its own way.",
        "",
        "Linux, macOS, Steam Deck:",
        "",
        *fence("sh", "\n".join(sh)),
        "",
        "Windows (PowerShell):",
        "",
        *fence("powershell", "\n".join(ps)),
    ]))
