"""The notes of a release, written from its record and the registry."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable

from core.text import series
from core.sizes import size_text
from model.guides import install_command
from model.platforms import load_platform_config
from model.releaserecord import pack_label, pack_owner
from model.registry import (
    list_registered_platforms,
    list_release_pack_platforms,
    load_platform_registry,
)


REPO = "Abdess/retrobios"
OWNER = "Abdess"
SITE = "https://abdess.github.io/retrobios/"
# The handheld app is served by the site, built from its own commit, never
# attached to a release. The installer's handheld section opens on the
# download of every system.
HANDHELD_PAGE = "wiki/installer/#on-a-handheld-the-retrobios-port"


def _extract_folders(record: dict, platforms_dir: str) -> dict[str, str]:
    """Pack name to the folder the registry says it extracts into."""
    registry = load_platform_registry(platforms_dir)
    folders: dict[str, str] = {}
    for name, pack in sorted(record.get("packs", {}).items()):
        folder = registry.get(pack_owner(name, pack), {}).get("extract_to")
        if folder:
            folders[name] = folder
    return folders


def without_pack(platforms_dir: str) -> list[str]:
    """Display names of the registered setups no release publishes a ZIP for."""
    released = set(list_release_pack_platforms(platforms_dir))
    names = [
        str(load_platform_config(key, platforms_dir).get("platform", key))
        for key in list_registered_platforms(platforms_dir)
        if key not in released
    ]
    return sorted(names, key=str.casefold)


def no_pack_paragraph(platforms_dir: str) -> list[str]:
    """One paragraph naming the setups served by the command alone. The
    packs published are the most downloaded ones (wiki/release-process.md,
    "Which platforms get a pack")."""
    names = without_pack(platforms_dir)
    if not names:
        return []
    listed = series(names)
    return [
        ("Only the most used setups have a pack, to keep the release small."
         f" For {listed}, use the command above."),
        "",
    ]


def _link(pack: dict, tag: str) -> str:
    """The pack's files on this release, one link per part."""
    base = f"https://github.com/{REPO}/releases/download/{tag}"
    assets = pack["assets"]
    if len(assets) == 1:
        return f"[Download]({base}/{assets[0]})"
    return ", ".join(f"[part {i}]({base}/{name})" for i, name in enumerate(assets, 1))


# Words the published notes of v2026.10.10 carried by hand: "never from a
# forum list" judged lists other people keep, and "a game never stops on a
# missing file" was a claim the gap analysis contradicts. Text about other
# projects says what changed, not who erred (wiki/release-process.md).
REFUSED = ("their file", "theirs", "of ours", "corrected", "wrong", "drift",
           "left out", "never seen", "forum", "never stops", "never fails")


def refused_words(text: str) -> list[str]:
    """The refused phrases the text holds, case ignored."""
    lowered = text.lower()
    return [phrase for phrase in REFUSED if phrase in lowered]


Run = Callable[[list[str]], str]


def _run(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout


def previous_record_commit(tag: str, run: Run | None = None) -> str:
    """The commit that recorded the release before *tag*: the oldest commit
    of the run of release.json changes that name the previous tag."""
    run = run or _run
    shas = run(["git", "log", "--format=%H", "--", "release.json"]).split()
    previous, base = None, None
    for sha in shas:
        recorded = json.loads(run(["git", "show", f"{sha}:release.json"])).get("tag")
        if previous is None:
            if recorded != tag:
                previous, base = recorded, sha
        elif recorded == previous:
            base = sha
        else:
            break
    if base is None:
        raise ValueError(f"release.json records no release before {tag}")
    return base


# Accounts that never helped: the owner's own, GitHub's placeholder for a
# deleted account, and spam (issue 32 by Bappo0 and pull request 67 by
# prakashmagat50-byte, both empty or garbage).
LEFT_OUT = frozenset(("Abdess", "Abdess76", "ghost", "Bappo0", "prakashmagat50-byte"))


def _person(login: str | None) -> str | None:
    """The login to thank, None for the owner, a bot, a deleted account,
    spam, or work GitHub links to no account."""
    if not login or login in LEFT_OUT or login.endswith("[bot]") or login.startswith("app/"):
        return None
    return login


def _logins(text: str) -> set[str]:
    """One login per line, as `gh api --paginate --jq` prints them."""
    return {person for line in text.splitlines() if (person := _person(line.strip()))}


def _authors(text: str) -> set[str]:
    """The authors of a `gh pr list` or `gh issue list --json author`."""
    return {person for item in json.loads(text)
            if not (item.get("author") or {}).get("is_bot")
            and (person := _person((item.get("author") or {}).get("login")))}


def gather_thanks(run: Run | None = None, repo: str = REPO) -> list[str]:
    """Everyone who helped since the repository started, each named once:
    commit authors as the commits API links them to an account and every
    pull request author, merged or not, then issue authors, then whoever
    commented on an issue or a pull request."""
    run = run or _run
    code = _logins(run(["gh", "api", "--paginate", f"repos/{repo}/commits",
                        "--jq", ".[] | .author.login // empty"]))
    code |= _authors(run(["gh", "pr", "list", "-R", repo, "--state", "all",
                          "--limit", "10000", "--json", "number,author"]))
    reports = _authors(run(["gh", "issue", "list", "-R", repo, "--state", "all",
                            "--limit", "10000", "--json", "number,author"])) - code
    helped = set()
    for path in (f"repos/{repo}/issues/comments", f"repos/{repo}/pulls/comments"):
        helped |= _logins(run(["gh", "api", "--paginate", path, "--jq", ".[] | .user.login"]))
    helped -= code | reports
    lines = []
    for label, people in (("Code and data", code), ("Reports", reports),
                          ("Help in issues", helped)):
        if people:
            names = [f"@{login}" for login in sorted(people, key=str.casefold)]
            lines.append(f"- **{label}**: {series(names)}.")
    return lines


def changelog_url(base: str, tag: str, repo: str = REPO) -> str:
    return f"https://github.com/{repo}/compare/{base[:9]}...{tag}"


def closing_lines(thanks: list[str], changelog: str) -> list[str]:
    """The Thanks section, left out when nobody is to thank, and the full
    changelog line."""
    # Folded: the lists run to a hundred names. GitHub renders the markdown
    # inside only with a blank line on each side of it.
    lines = (["### Thanks", "", "<details>",
              "<summary>Everyone who helped since the start</summary>", "",
              *thanks, "", "</details>", ""]
             if thanks else [])
    return [*lines, f"**Full changelog**: {changelog}", ""]


def render(record: dict, platforms_dir: str, whats_new: str,
           closing: list[str] | None = None) -> str:
    packs = record.get("packs", {})
    folders = _extract_folders(record, platforms_dir)
    tag = str(record.get("tag", ""))
    lines = [
        "### Get the BIOS files",
        "",
        "Paste this in a terminal. It finds the setup and installs the missing BIOS files.",
        "",
        "**Linux, macOS, Steam Deck**",
        "```sh",
        install_command("sh"),
        "```",
        "",
        "**Windows**",
        "```powershell",
        install_command("powershell"),
        "```",
        "",
        f"**On a handheld**: [get the app for the system]({SITE}{HANDHELD_PAGE}).",
        "",
        "### Full packs",
        "",
        "Large downloads, for a device without internet. Extract into the BIOS folder.",
        "",
    ]
    if any(len(pack["assets"]) > 1 for pack in packs.values()):
        lines += [
            ("A pack in parts: each part is an ordinary ZIP. Extract every part into"
             " the same folder. Nothing needs joining."),
            "",
        ]
    lines += [
        "| Platform | Download | Size | Files | Extract to |",
        "|----------|----------|-----:|------:|-----------|",
    ]
    for name, pack in sorted(packs.items(), key=lambda item: -item[1]["extracted_size"]):
        folder = folders.get(name)
        lines.append(
            f"| {pack_label(name)} | {_link(pack, tag)} |"
            f" {size_text(pack['extracted_size'])} | {pack['files']:,} |"
            f" {f'`{folder}`' if folder else '-'} |"
        )
    lines += [
        "",
        f"Files no pack holds yet: [gap analysis]({SITE}gaps/).",
        "",
        *no_pack_paragraph(platforms_dir),
        whats_new.strip(),
        "",
        *(closing or []),
    ]
    return "\n".join(lines)
