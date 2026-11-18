"""Each platform's page, and the files page."""

from __future__ import annotations

import json
import re

from model.guides import GUIDES
from model.systemnames import system_name
from resolve.nativemode import check_label, reads_file_contents
from sitegen import markup
from sitegen.config import REPO_URL, _date_line
from sitegen.decorate import level_label
from sitegen.diagrams import local_images
from sitegen.guidepage import _pack_buttons, _platform_guide
from sitegen.home import _stat
from sitegen.install import _platform_install_block
from sitegen.platformfiles import (
    ROLE_LEGEND,
    ROLE_LEGEND_TITLE,
    _EXPORTED,
    _core_folders_section,
    _declared_by_system,
    _emulator_named_link,
    _launcher_unproven_section,
    _platform_data_links,
    _render_platform_systems,
    _system_emulators,
)
from sitegen.render import _escape_tags, _pct


# A hash a platform's list writes, in words.
_HASH_WORDS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "crc32": "CRC32"}


def _transcribed_row(config: dict) -> list[str]:
    """The file every declaration on this page was read from: without it
    a hash could not be traced to the revision that states it."""
    from sitegen.sources import list_source

    transcribed = str(config.get("source") or "")
    if not transcribed:
        return []
    listed = list_source(transcribed)
    moving = (listed.moving if listed else bool(
        re.search(r"/(?:master|main|db)(?:/|$)|refs/heads/", transcribed)))
    note = " (a branch: the revision read is not recorded)" if moving else ""
    # Named in words: the raw URL broke into 25 lines of 8 characters
    # on a phone.
    link = (f"[{_escape_tags(listed.label)}]({listed.browse()})" if listed
            else f"<{transcribed}>")
    return [f"| Transcribed from | {link}{note} |"]


def _platform_meta_rows(name: str, config: dict, mode: str, registry: dict) -> list[str]:
    """The rows of a platform's detail card."""
    rows = []
    homepage = config.get("homepage", "")
    version = config.get("version", "")
    hash_type = config.get("hash_type", "")
    base_dest = config.get("base_destination", "")
    # The hash the list writes, when it is not the one the platform checks:
    # RetroArch checks presence and its System.dat writes sha1.
    if hash_type and hash_type != mode:
        rows.append(f"| Hashes in the list | {_HASH_WORDS.get(hash_type, hash_type)} |")
    if version:
        rows.append(f"| Version | {version} |")
    # base_destination is only the root the platform's own list writes its
    # paths from: the pack strips it, so it is no folder to extract into.
    if base_dest:
        rows.append(f"| Paths in the platform's list start at | `{base_dest}/` |")
    if homepage:
        rows.append(f"| Homepage | [{homepage}]({homepage}) |")
    rows.extend(_transcribed_row(config))
    if name in _EXPORTED:
        rows.append(f"| Updated file | [Download it and see the changes](../exports.md#{name}) |")
    rows.append(f"| Data | {_platform_data_links(name)} |")
    for cb in registry.get(name, {}).get("contributed_by", []) or []:
        username = cb.get("username", "")
        contribution = cb.get("contribution", "")
        pr = cb.get("pr")
        pr_link = f" ([#{pr}]({REPO_URL}/pull/{pr}))" if pr else ""
        rows.append(
            f"| Contributed by | [@{username}](https://github.com/{username}):"
            f" {contribution}{pr_link} |"
        )
    return rows


def _platform_band(cov: dict) -> list[str]:
    """The coverage figures above a platform's detail card."""
    config = cov["config"]
    mode = cov["mode"]
    pct = _pct(cov["present"], cov["total"])
    mode_badge = (
        "rb-badge-success" if reads_file_contents(mode) else "rb-badge-info"
    )
    return [
        markup.block_open("div", 'class="rb-stats"'),
        "",
        *_stat(f"{cov['present']}/{cov['total']}", f"Coverage ({pct})"),
        *_stat(str(cov["verified"]), "Verified"),
        *_stat(str(cov["missing"]), "Missing"),
        *_stat(f'<span class="rb-badge {mode_badge}">{check_label(mode, config.get("hash_rule"))}</span>',
               "Checked by"),
        "</div>",
        "",
    ]


def _platform_declarations(cov: dict) -> tuple[dict[tuple[str, str], list[dict]], dict[str, list]]:
    """The declarations of a platform's list by system and name, and its
    verify details by system."""
    # The declaration behind each detail, by system and name in declaration
    # order: keyed by name alone, the last of MiSTer's 23 boot.rom gave its
    # MD5 to every system's row.
    config_files: dict[tuple[str, str], list[dict]] = {}
    for sys_id, system in cov["config"].get("systems", {}).items():
        for fe in system.get("files", []):
            fname = fe.get("name", "")
            if fname:
                config_files.setdefault((sys_id, fname), []).append(fe)

    by_system: dict[str, list] = {}
    for d in cov["details"]:
        sys_id = d.get("system", "unknown")
        by_system.setdefault(sys_id, []).append(d)
    return config_files, by_system


def _platform_head(name: str, cov: dict, registry: dict, no_list: bool) -> list[str]:
    """A platform page down to its reference heading's notes: the title,
    the summary and the guide."""
    config = cov["config"]
    display = cov["platform"]
    homepage = config.get("homepage", "")
    # The mark is drawn beside the title from the front matter: floated
    # beside the first line at 48 px it read as a broken image.
    logo_url = registry.get(name, {}).get("logo", "")
    logo_url = local_images().get(logo_url, logo_url)

    lines = [
        *(["---", f"logo: {json.dumps(logo_url)}", "---", ""] if logo_url else []),
        f"# {display}",
        "",
    ]

    summary = GUIDES[name].summary if name in GUIDES else ""
    if summary:
        lines += [summary + (f" [{display} website]({homepage})." if homepage else ""), ""]

    if name in GUIDES:
        lines += _platform_guide(name, display, cov, registry, no_list)
    lines += [
        "## Reference: every file by system { #reference-every-file-by-system }",
        "",
        level_label("reference"),
        "",
        "For checking the work: counts, the list's source and each file's hashes.",
        "",
        *(line for note in (GUIDES[name].reference_notes if name in GUIDES else ())
          for line in (note, "")),
    ]
    if no_list:
        # MinUI and its forks hand each core a folder and name no file: a
        # 0/0 coverage band read as "this device is not supported".
        lines.extend(markup.aside("info", "No BIOS list of its own", [
            f"{display} names no BIOS file itself: it gives each emulator core "
            "its own folder and the core looks for its files there. The pack "
            "places every file the cores it runs need into those folders. The "
            "core files are listed further down this page.",
        ]))
    return lines


def generate_platform_page(
    name: str,
    cov: dict,
    registry: dict | None = None,
    emulator_files: dict | None = None,
    moved: dict[str, str] | None = None,
) -> str:
    """A guide first (folder, command, pack, check), then every file the
    platform's list and its emulators need, under a reference heading.

    ``moved`` collects the pages of systems whose list is too long for it.
    """
    registry = registry or {}
    config = cov["config"]
    display = cov["platform"]

    no_list = not cov["total"] and registry.get(name, {}).get("native_list") == "none"
    lines = _platform_head(name, cov, registry, no_list)
    band = [] if no_list else _platform_band(cov)
    lines.extend([*band, markup.block_open("div", 'class="rb-meta-card"'), "",
                  "| Detail | Value |", "|---|---|"])
    lines.extend(_platform_meta_rows(name, config, cov["mode"], registry))
    lines.extend(["", "</div>"])
    if name not in GUIDES:
        detect = (registry.get(name, {}).get("install") or {}).get("detect") or []
        on_card = any(rule.get("method") == "card_marker" for rule in detect)
        lines.extend(["", *_platform_install_block(name, display, on_card)])
        lines.extend(["", _pack_buttons(name, f"Download {display} Pack", display=display)])
    lines.append("")

    config_files, by_system = _platform_declarations(cov)

    if no_list:
        lines.extend(_core_folders_section(name, config))
    if _own_list_only(config):
        lines.extend([f"**Cores:** {OWN_LIST_ONLY}", ""])

    # System summary table (quick navigation)
    lines.extend(
        [] if no_list and not by_system else [
            "### Systems overview",
            "",
            "| System | Files | Status | Emulators |",
            "|--------|-------|--------|-----------|",
        ]
    )
    by_system_declared = _declared_by_system(config_files)
    for sys_id, files in sorted(by_system.items()):
        ok_count = sum(1 for f in files if f["status"] == "ok")
        total = len(files)
        non_ok = total - ok_count
        if non_ok == 0:
            status = '<span class="rb-badge rb-badge-success">OK</span>'
        else:
            status = (
                f'<span class="rb-badge rb-badge-warning">'
                f'{non_ok} issue{"s" if non_ok > 1 else ""}</span>'
            )
        sys_emus = _system_emulators(sys_id, emulator_files, by_system_declared.get(sys_id))
        anchor = sys_id.replace(" ", "-")
        # Named and linked as the detail blocks below do: the column held
        # profile ids, none of 1,463 linked.
        emu_str = ", ".join(_emulator_named_link(e, "../") for e in sorted(sys_emus)[:3])
        if len(sys_emus) > 3:
            emu_str += f" [+{len(sys_emus) - 3}](#{anchor})"
        # The name a reader filters on, the id the list writes beside it.
        # The id and the count are no words a reader searches for: indexed,
        # every platform page answered a system id before its system's page.
        lines.append(
            f"| [{_escape_tags(system_name(sys_id))}](#{anchor}) "
            f"<small data-pagefind-ignore>{sys_id}</small> "
            f"| <span data-pagefind-ignore>{ok_count}/{total}</span> | {status} | {emu_str} |"
        )
    lines.append("")
    if by_system:
        lines.extend(markup.details("note", ROLE_LEGEND_TITLE, [ROLE_LEGEND]))

    lines.extend(
        _render_platform_systems(by_system, config_files, emulator_files,
                                 (name, display), moved, config)
    )
    lines.extend(_launcher_unproven_section(config))

    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


# What a platform that declares no core (cores: []) is told, on its page
# and in the cross-reference.
OWN_LIST_ONLY = "None. Its own list is the whole truth: no core profile adds a file."


def _own_list_only(config: dict) -> bool:
    """The platform declares `cores: []`: its own list decides alone."""
    return isinstance(config.get("cores"), list) and not config["cores"]
