"""The cross-reference page: emulators against platforms and upstream projects."""

from __future__ import annotations

import re
import urllib.parse

from model.systemnames import system_name
from resolve.cores import resolve_platform_cores
from sitegen import markup
from sitegen.config import date_line
from sitegen.emulatorsindex import CLS_LABEL_ONE
from sitegen.parts import parent_front_matter
from sitegen.platformpage import OWN_LIST_ONLY, own_list_only
from sitegen.render import count_text, escape_tags


def _core_scope_note(config: dict, profiles: dict) -> str:
    """" (all libretro)" when the platform resolves every libretro core.

    Read from what resolve_platform_cores returns, not from the shape of
    ``cores:``: RetroPie and RetroDECK name ``retroarch`` in a list, which
    pulls in every libretro core as ``all_libretro`` does, and the label
    showed for RetroArch and Lakka only.
    """
    every_libretro = resolve_platform_cores({"cores": "all_libretro"}, profiles)
    resolved = resolve_platform_cores(config, profiles)
    if not every_libretro or not every_libretro <= resolved:
        return ""
    others = len(resolved - every_libretro)
    if not others:
        return " (all libretro)"
    return f" (all libretro, plus {count_text(others, 'other core')})"


def gap_sources(data: dict) -> dict[str, int]:
    """Where each undeclared file of one emulator comes from.

    A file the emulator's own package installs is not one to find. The
    report's gap_missing counts it, and the gaps page announced 1,356 files
    to source where 609 are, with a red badge on emulators that have none.
    """
    counts = {"bios": 0, "data": 0, "large_file": 0, "bundled": 0, "missing": 0}
    for gap in data.get("gap_details") or []:
        source = gap.get("source", "")
        if source == "missing" and gap.get("bundled"):
            source = "bundled"
        if source in counts:
            counts[source] += 1
    return counts


def _xref_upstream(profile: dict) -> str:
    """The project a core comes from: its upstream, else its own source."""
    raw = profile.get("upstream") or profile.get("source", "")
    return raw if isinstance(raw, str) else ""


_FORGES = frozenset({
    "github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "git.eden-emu.dev",
    "git.ryujinx.app",
})


def upstream_project(url: str) -> tuple[str, str]:
    """(project key, revision or path inside it) for an upstream URL.

    MAME was twelve rows: mamedev/mame and one row per release tree
    (mamedev/mame/tree/mame0289 and the rest). On a forge the project is
    owner/repo, a GitLab project every group before `/-/`, and the rest is
    a revision. Elsewhere the address without its scheme, `www.` and
    trailing slash is the project. A note written after the address
    (`... (sys/src/games/nes/)`) is a path inside it.
    """
    url, _, note = url.strip().partition(" ")
    note = note.strip().strip("()")
    if not url.startswith(("http://", "https://")):
        return " ".join(filter(None, (url, note))), ""
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc.lower().removeprefix("www.")
    parts = [p for p in parsed.path.split("/") if p]
    if host == "gitlab.com" and len(parts) >= 2:
        cut = parts.index("-") if "-" in parts else len(parts)
        rest = parts[cut + 1:]
        if rest[:1] in (["tree"], ["blob"]):
            rest = rest[1:]
        return f"{host}/{'/'.join(parts[:cut])}", "/".join(filter(None, ("/".join(rest), note)))
    if host in _FORGES and len(parts) >= 2:
        repo = parts[1].removesuffix(".git")
        rest = parts[2:]
        if rest[:1] in (["tree"], ["blob"], ["src"]):
            rest = rest[1:]
        return f"{host}/{parts[0]}/{repo}", "/".join(filter(None, ("/".join(rest), note)))
    return "/".join([host, *parts]), note


def _upstream_label(key: str) -> str:
    """owner/repo on GitHub, host/owner/repo on another forge, and a
    Software Heritage revision by its short id."""
    swh = re.fullmatch(r"archive\.softwareheritage\.org/browse/revision/([0-9a-f]{12})[0-9a-f]*", key)
    if swh:
        return f"Software Heritage revision {swh[1]}"
    return key.removeprefix("github.com/")


def _breakable(label: str) -> str:
    """A project address that may wrap after each slash: unbroken, the
    longest pushed three of five columns off a 1,440 px screen."""
    return "/<wbr>".join(escape_tags(part) for part in label.split("/"))


def _xref_platform_rows(config: dict, unique: dict) -> tuple[int, list[str]]:
    """The cores a platform pulls in, as table rows, with their count."""
    # The cores the builder and verify resolve: a hand copy here dropped
    # the libretro set a list naming retroarch pulls in, and the system
    # fallback EmuDeck relies on.
    matched = sorted(key for key in resolve_platform_cores(config, unique) if key in unique)
    rows = []
    for emu_name in matched:
        p = unique[emu_name]
        cls_raw = p.get("core_classification", "-")
        systems = p.get("systems", []) or []
        sys_str = ", ".join(escape_tags(system_name(s)) for s in systems[:3])
        if len(systems) > 3:
            sys_str += f" +{len(systems) - 3}"
        files = p.get("files", []) or []
        libretro_only = sum(1 for f in files if f.get("mode") == "libretro")
        standalone_only = sum(1 for f in files if f.get("mode") == "standalone")
        file_str = str(len(files))
        parts = [f"{n} {label}" for n, label in ((libretro_only, "libretro-only"),
                                                  (standalone_only, "standalone-only")) if n]
        if parts:
            file_str += f" ({', '.join(parts)})"
        upstream = _xref_upstream(p)
        key, _rest = upstream_project(upstream)
        upstream_display = (f"[{_breakable(_upstream_label(key))}]({upstream.split()[0]})"
                            if upstream.startswith("http") else (escape_tags(upstream) or "-"))
        rows.append(
            f"| [{escape_tags(p.get('emulator', emu_name))}](emulators/{emu_name}.md) "
            f"| {CLS_LABEL_ONE.get(cls_raw, cls_raw)} | {sys_str or '-'} | {file_str} "
            f"| {upstream_display} |"
        )
    return len(matched), rows


def _render_xref_by_platform(
    coverages: dict, unique: dict, moved: dict[str, str] | None = None,
) -> list[str]:
    """Which cores each platform pulls in: counts here, a page per platform.

    One page held every platform's table, 30,551 nodes: the overview keeps
    the counts and each platform's table moves to ``moved`` by stem.
    """
    lines = [
        "## By platform",
        "",
        "| Platform | Cores | Core list |",
        "|----------|------:|-----------|",
    ]
    for pname in sorted(coverages, key=lambda x: coverages[x]["platform"]):
        cov = coverages[pname]
        display = cov["platform"]
        config = cov["config"]
        count, rows = _xref_platform_rows(config, unique)
        stem = f"cross-reference-{pname}"
        if own_list_only(config):
            # cores: [] (MiSTer, BizHawk): no profile describes what they
            # read, and a page of cores would be an empty table.
            lines.append(f"| [{escape_tags(display)}](platforms/{pname}.md) | 0 "
                         f"| {OWN_LIST_ONLY} |")
            continue
        lines.append(
            f"| [{escape_tags(display)}](platforms/{pname}.md) | {count}"
            f"{_core_scope_note(config, unique)} | [Cores on {escape_tags(display)}]({stem}.md) |"
        )
        if moved is not None:
            moved[stem] = "\n".join([
                "---", "level: reference",
                *parent_front_matter(("Cores by platform", "/cross-reference/")), "---", "",
                f"# Cores on {display}",
                "",
                f"{count_text(count, 'core')}{_core_scope_note(config, unique)} that "
                f"{display} runs, the systems each emulates and the project it comes "
                f"from. Part of [Cores by platform](cross-reference.md). The files "
                f"are listed on the [{display} page](platforms/{pname}.md).",
                "",
                "| Core | Classification | Systems | Files | Upstream |",
                "|------|---------------|---------|-------|----------|",
                *rows,
                "",
            ]) + "\n"
    lines.append("")
    return lines


def _render_xref_by_upstream(
    coverages: dict, unique: dict
) -> list[str]:
    """The same relation read the other way: one row per upstream project."""
    lines: list[str] = [
        "## By upstream emulator",
        "",
        "One row per project: the releases and folders of one repository are "
        "listed in the Revisions column. Platforms counts the platforms that run "
        "at least one of its cores.",
        "",
        "| Cores | Upstream | Revisions | Classification | Platforms |",
        "|-------|----------|-----------|----------------|----------:|",
    ]

    by_upstream: dict[str, list[tuple[str, str, str]]] = {}
    for emu_name, p in sorted(unique.items()):
        # A null upstream is the project's own source: grouping it under
        # the string "None" put eight unrelated engines in one row.
        up_str = _xref_upstream(p)
        if up_str:
            key, rest = upstream_project(up_str)
            by_upstream.setdefault(key, []).append((emu_name, up_str, rest))

    platform_membership: dict[str, set[str]] = {}
    for cov in coverages.values():
        for key in resolve_platform_cores(cov["config"], unique):
            platform_membership.setdefault(key, set()).add(cov["platform"])

    for key in sorted(by_upstream, key=lambda k: _upstream_label(k).casefold()):
        members = by_upstream[key]
        cores = sorted(c for c, _url, _rest in members)
        classifications = sorted({
            CLS_LABEL_ONE.get(unique[c].get("core_classification", "-"),
                           unique[c].get("core_classification", "-"))
            for c in cores
        })
        plats = sorted(set().union(*(platform_membership.get(c, set()) for c in cores)))
        revisions = sorted({rest for _c, _url, rest in members if rest})
        urls = sorted({url.split()[0] for _c, url, _rest in members})
        # The project's own address: the bare one when a core cites it.
        home = next((u for u in urls if not upstream_project(u)[1]), urls[0])
        upstream_cell = (f"[{_breakable(_upstream_label(key))}]({home})" if home.startswith("http")
                         else escape_tags(key))
        lines.append(
            "| " + ", ".join(f"[{c}](emulators/{c}.md)" for c in cores)
            + f" | {upstream_cell} | {', '.join(_breakable(r) for r in revisions) or '-'} "
            f"| {', '.join(classifications)} | {len(plats)} |"
        )
    return lines


def generate_cross_reference(
    coverages: dict,
    profiles: dict,
    moved: dict[str, str] | None = None,
) -> str:
    """Cross-reference: counts per platform, then cores by upstream project.

    ``moved`` collects one page per platform with its core table.
    """
    unique = {
        k: v for k, v in profiles.items() if v.get("type") != "alias" and v.get("role") != "test"
    }

    total_cores = len(unique)
    total_upstreams = len({
        upstream_project(_xref_upstream(p))[0] for p in unique.values() if _xref_upstream(p)
    })
    # "623 cores across 18 platforms" counted every profile: 91 of them
    # no platform runs.
    run_cores = len({
        key for cov in coverages.values()
        for key in resolve_platform_cores(cov["config"], unique)
    })

    lines = [
        "# Cores by platform",
        "",
        "Every core each platform runs, the systems it emulates, and the project "
        "it comes from. A core built for RetroArch is often a port of another "
        "emulator, and the two can differ in the files they read and the checks "
        "they make, so each core names its upstream project. "
        f"{total_cores} cores are profiled, {run_cores} of them run by the "
        f"{len(coverages)} platforms, and they come from {total_upstreams} "
        "upstream projects.",
        "",
        "The files a platform's emulators load and its own list does not name are "
        "counted on [What the packs do not hold](gaps.md).",
        "",
        " ".join([
            markup.button("Download cross-reference CSV", "downloads/cross-reference.csv"),
            markup.button("Open emulator API", "api/v1/emulators.json"),
            markup.button("All data exports", "data.md"),
        ]),
        "",
    ]

    lines.extend(_render_xref_by_platform(coverages, unique, moved))
    lines.extend(_render_xref_by_upstream(coverages, unique))

    lines.extend(["", date_line()])
    return "\n".join(lines) + "\n"
