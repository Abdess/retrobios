"""Scraper for RetroPie package availability per platform.

Source: https://github.com/RetroPie/RetroPie-Setup/tree/<rev>/scriptmodules,
read from the tarball of the revision platforms/retropie.yml was scraped at.
Parses rp_module_id and rp_module_flags from each scriptmodule of the
package sections the platform list reads (emulators, libretrocores, ports)
to determine which platforms each package supports.
"""

from __future__ import annotations

import sys
import tarfile
from datetime import datetime, timezone

from ..retropie_modules import PLATFORM_FLAGS, module_enabled, module_fields
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

ARCH_MAP: dict[str, str] = {
    "rpi1": "armv6",
    "rpi2": "armv7",
    "rpi3": "armv7",
    "rpi4": "aarch64",
    "rpi5": "aarch64",
    "x86": "x86",
    "x86_64": "x86_64",
}

def _fetch_archive(url: str) -> bytes:
    try:
        return fetch_archive(url)
    except (ConnectionError, ValueError) as exc:
        raise RuntimeError(str(exc)) from exc


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
            fields = module_fields(content)
            module_id = fields.get("id")
            if not module_id:
                print(f"  warning: no rp_module_id in {filename}", file=sys.stderr)
                continue
            # The platform scraper names the package the same way.
            for platform in PLATFORM_FLAGS:
                if module_enabled(fields.get("flags", "").split(), PLATFORM_FLAGS[platform]):
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
