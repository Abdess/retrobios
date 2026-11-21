"""What the recorded release serves for each platform: pack totals, state and download links."""

from __future__ import annotations

from collections.abc import Callable

from model import releaserecord
from sitegen.install import has_release_pack


def release_totals(platform_name: str, record: dict) -> tuple[int | None, int | None]:
    """Files and bytes of the pack the latest release serves for a platform.

    The Download link gives that release, so these are the figures a reader
    can check against an extraction. The install manifests describe what
    main would build today, which is a different pack as soon as a commit
    lands after the release. Returns (None, None) for a platform the release
    carries no pack for.
    """
    pack = releaserecord.pack_for(platform_name, record)
    if not pack:
        return None, None
    return pack["files"], pack["extracted_size"]


def release_state(platform_name: str, record: dict) -> str:
    """"none" for a setup no release publishes a ZIP for (`release_pack`),
    "pending" for one the recorded release carries no pack for, added since,
    else "released". No recorded tag, no release to be missing from."""
    if not has_release_pack(platform_name):
        return "none"
    pack = releaserecord.pack_for(platform_name, record)
    if record.get("tag") and not (pack and pack.get("assets")):
        return "pending"
    return "released"


NO_PACK = "Use the command"


def asset_links(
    platform_name: str, record: dict, repo: str, label: str, attrs: str = "",
    button: Callable[[str, str], str] | None = None,
) -> str:
    """Markdown links to the files of a platform's pack in the recorded release.

    Written on the platform's get/ page only: every other surface links that
    page, whose address does not change with the release. A pack published
    whole gets one link labelled *label*. A pack in parts gets one link per
    part, since every part is needed, after the number of files to download:
    a reader who took one link for the pack extracted half of it. *repo* is
    the repository URL, *attrs* an attribute list put after each link, or
    *button* the function that draws each link as a button. Without a
    recorded release the link is the latest release page.
    """
    pack = releaserecord.pack_for(platform_name, record)
    tag = record.get("tag")
    assets = pack.get("assets") if pack else None
    def link(text: str, url: str) -> str:
        return button(text, url) if button else f"[{text}]({url}){attrs}"

    if not tag or not assets:
        return link(label, f"{repo}/releases/latest")
    urls = [f"{repo}/releases/download/{tag}/{asset}" for asset in assets]
    if len(urls) == 1:
        return link(label, urls[0])
    styled = bool(attrs or button)
    parts = [
        link(f"{'P' if styled else 'p'}art {number} of {len(urls)}", url)
        for number, url in enumerate(urls, 1)
    ]
    if styled:
        return f"{len(urls)} files to download, all needed: " + " ".join(parts)
    return f"{label}, {len(urls)} files, all needed: " + ", ".join(parts)


def download_links(
    platform_name: str, record: dict, label: str, attrs: str = "",
    button: Callable[[str, str], str] | None = None,
    site: str = "", page: str | None = None,
) -> str:
    """The download cell of a platform: its permanent get/ page.

    *record* is the release record reduced to the release_pack platforms
    (release_record.advertised). A platform with a pack in it gets *label*
    linked to its page, which lists the files of the current release. A
    platform marked release_pack but missing from the release, added since,
    gets "No ZIP yet". Any other platform is served by the installer, and
    the cell says so instead of staying empty. *site* is the site root the
    get/ address hangs from, or *page* the address itself as the site links
    it, and *attrs* and *button* style the link.
    """
    page = page or releaserecord.get_page(platform_name, site)
    def link(text: str) -> str:
        return button(text, page) if button else f"[{text}]({page}){attrs}"

    state = release_state(platform_name, record)
    if state == "none":
        return link(NO_PACK)
    if state == "pending":
        return f"No ZIP yet: {link(NO_PACK.lower())}"
    return link(label)
