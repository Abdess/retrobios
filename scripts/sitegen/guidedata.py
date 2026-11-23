"""The guides of the platforms folder the site run describes (siteinputs)."""

from __future__ import annotations

from model import guides
from model import siteinputs
from model.guides import Guide, HandheldGuide, Tile


def loaded() -> dict:
    return guides.loaded(siteinputs.current().platforms)


def platform_guides() -> dict[str, Guide]:
    return loaded()["guides"]


def install_base() -> str:
    return loaded()["install_base"]


def install_sh() -> str:
    """The sh bootstrap the site serves (sitegen/bootstrap.py writes it)."""
    return guides.install_sh(install_base())


def install_ps1() -> str:
    """The PowerShell bootstrap the site serves."""
    return guides.install_ps1(install_base())


def install_command(shell: str, args: str = "") -> str:
    """The one-liner for a shell, as the site prints it."""
    return guides.install_command(shell, args, base=install_base())


def device_groups() -> dict[str, tuple[str, str]]:
    return loaded()["device_groups"]


def group_anchors() -> dict[str, str]:
    return loaded()["group_anchors"]


def also_runs() -> dict[str, tuple[tuple[str, str, str, str, str], ...]]:
    return loaded()["also_runs"]


def group_tiles() -> dict[str, tuple[Tile, ...]]:
    return loaded()["tiles"]


def handheld_guide() -> HandheldGuide | None:
    return loaded()["handheld_guide"]


def terminals() -> dict[str, tuple[str, str, str]]:
    return loaded()["terminals"]


def trust_items() -> tuple[str, ...]:
    return loaded()["trust_items"]


def folder_list(name: str, registry: dict | None = None) -> list[tuple[str, str]]:
    """Every folder a guide names (model.guides.folder_list)."""
    return guides.folder_list(name, siteinputs.current().platforms, registry)


def setup_count() -> int:
    """Setups the site covers: every registered platform, since each keeps
    its page, its pack and its command. The one count every page states."""
    return len(platform_guides())
