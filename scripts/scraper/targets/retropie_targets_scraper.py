"""Scraper for RetroPie package availability per platform.

Source: https://github.com/RetroPie/RetroPie-Setup/tree/<rev>/scriptmodules,
read from the tarball of the revision platforms/retropie.yml was scraped at.
Parses rp_module_id and rp_module_flags from each scriptmodule of the
package sections the platform list reads (emulators, libretrocores, ports)
to determine which platforms each package supports.
"""

from __future__ import annotations

import re
import sys
import tarfile
from datetime import datetime, timezone

from ..retropie_scraper import SOURCE_URL, core_name, fetch_archive, script_members
from . import BaseTargetScraper, target_cli

PLATFORM_NAME = "retropie"

# Written as the targets file's source: the scriptmodules tree at the pin.
GITHUB_API_URL = (
    "https://api.github.com/repos/RetroPie/RetroPie-Setup/contents/scriptmodules"
)
# The sections the platform scraper reads: a standalone package missing here
# is filtered out of every targeted pack.
PACKAGE_DIRS = ("emulators", "libretrocores", "ports")

# The flags RetroPie's set_platform_defaults, cpu_* and platform_* functions
# give each platform (scriptmodules/system.sh), with the video stack of the
# images it ships: videocore and dispmanx on rpi1-3, kms with fkms dispmanx
# on rpi4 (buster), kms on rpi5.
PLATFORM_FLAGS: dict[str, set[str]] = {
    "rpi1": {"rpi1", "32bit", "arm", "armv6", "rpi", "gles", "videocore", "dispmanx"},
    "rpi2": {"rpi2", "32bit", "arm", "armv7", "neon", "rpi", "gles", "videocore",
             "dispmanx"},
    "rpi3": {"rpi3", "32bit", "arm", "armv8", "neon", "rpi", "gles", "videocore",
             "dispmanx"},
    "rpi4": {"rpi4", "32bit", "arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31",
             "mesa", "kms", "dispmanx"},
    "rpi5": {"rpi5", "32bit", "arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31",
             "mesa", "kms"},
    "x86": {"x86", "32bit", "gl", "vulkan", "x11"},
    "x86_64": {"x86", "64bit", "gl", "vulkan", "x11"},
}

ARCH_MAP: dict[str, str] = {
    "rpi1": "armv6",
    "rpi2": "armv7",
    "rpi3": "armv7",
    "rpi4": "aarch64",
    "rpi5": "aarch64",
    "x86": "x86",
    "x86_64": "x86_64",
}

_MODULE_ID_RE = re.compile(r'rp_module_id\s*=\s*["\']([^"\']+)["\']')
_MODULE_FLAGS_RE = re.compile(r'rp_module_flags\s*=\s*["\']([^"\']*)["\']')


def _fetch_archive(url: str) -> bytes:
    try:
        return fetch_archive(url)
    except (ConnectionError, ValueError) as exc:
        raise RuntimeError(str(exc)) from exc


def _is_available(flags_str: str, platform: str) -> bool:
    """Whether RetroPie enables a module on *platform*.

    Port of rp_registerModule (scriptmodules/packages.sh): flags are read in
    order from an enabled default; !all disables, a flag the platform has
    enables, !flag disables when the platform has it. A flag the platform
    does not know (sdl1, nodistcc) changes nothing, and a comparison against
    the build host (:$__gcc_version:-lt:7) cannot be decided here, so it
    leaves the module as it was.
    """
    platform_has = PLATFORM_FLAGS.get(platform, set())
    enabled = True
    for token in flags_str.split():
        if token == "!all":
            enabled = False
        elif token in platform_has:
            enabled = True
        elif token.startswith("!") and token[1:] in platform_has:
            enabled = False
    return enabled


def _parse_module(content: str) -> tuple[str | None, str]:
    """Return (module_id, flags_string) from a scriptmodule file."""
    id_match = _MODULE_ID_RE.search(content)
    flags_match = _MODULE_FLAGS_RE.search(content)
    module_id = id_match.group(1) if id_match else None
    flags = flags_match.group(1) if flags_match else ""
    return module_id, flags


class Scraper(BaseTargetScraper):
    """Fetches RetroPie package availability by parsing scriptmodules."""

    def __init__(self, url: str = GITHUB_API_URL, revision: str | None = None) -> None:
        super().__init__(url=url)
        self._revision = revision

    @property
    def revision(self) -> str:
        """The commit the package list was read at: the flags of another
        revision filter packages the platform file does not describe."""
        if self._revision is None:
            self._revision = self.pinned_revision(PLATFORM_NAME)
        return self._revision

    def _scriptmodules(self) -> dict[str, str]:
        """section/filename to text for every .sh of the package sections,
        read from the tarball of the pinned revision in one request."""
        url = SOURCE_URL.format(rev=self.revision)
        modules: dict[str, str] = {}
        try:
            for relative, text in script_members(_fetch_archive(url)):
                parts = relative.split("/")
                if len(parts) == 3 and parts[0] == "scriptmodules" and parts[1] in PACKAGE_DIRS:
                    modules[f"{parts[1]}/{parts[2]}"] = text
        except tarfile.TarError as exc:
            raise RuntimeError(f"{url}: {exc}") from exc
        for section in PACKAGE_DIRS:
            if not any(name.startswith(f"{section}/") for name in modules):
                raise RuntimeError(f"no scriptmodules under {section}/ in {url}")
        return dict(sorted(modules.items()))

    def fetch_targets(self) -> dict:
        print("  reading RetroPie scriptmodules...", file=sys.stderr)
        modules = self._scriptmodules()

        # A libretro and a standalone package can share a name (lr-dosbox,
        # dosbox): a core list names each once.
        platform_cores: dict[str, set[str]] = {p: set() for p in PLATFORM_FLAGS}

        for filename, content in modules.items():
            module_id, flags = _parse_module(content)
            if not module_id:
                print(f"  warning: no rp_module_id in {filename}", file=sys.stderr)
                continue
            # The platform scraper names the package the same way.
            for platform in PLATFORM_FLAGS:
                if _is_available(flags, platform):
                    platform_cores[platform].add(core_name(module_id))

        print(f"  parsed {len(modules)} scriptmodules", file=sys.stderr)

        targets: dict[str, dict] = {}
        for platform, arch in ARCH_MAP.items():
            cores = sorted(platform_cores.get(platform, []))
            targets[platform] = {
                "architecture": arch,
                "cores": cores,
            }

        return {
            "platform": "retropie",
            "source": f"{self.url}?ref={self.revision}",
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    target_cli(Scraper, "Scrape RetroPie package targets from scriptmodules")


if __name__ == "__main__":
    main()
