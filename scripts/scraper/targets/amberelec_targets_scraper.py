"""Scraper for AmberELEC per-device emulator availability.

Sources (AmberELEC/AmberELEC, at the commit platforms/amberelec.yml names):
  - Makefile -- one `DEVICE=<name> ARCH=<arch> ./scripts/build_distro` target
    per image (RG351P, RG351V, RG351MP, RG552, RG353, RG503 at a21975bf)
  - packages/amberelec/package.mk -- LIBRETRO_CORES_EXTRA joins PKG_EMUS
    only on the devices its `if` names (lines 23-31 at a21975bf: RG552,
    RG353, RG503), and on every other device makeinstall_target deletes
    each of those cores from es_systems.cfg (lines 45-58)
  - packages/ui/emulationstation/config/es_systems.cfg -- read the way the
    platform scraper reads it, after that deletion

An RG351P image carries neither melonDS nor bsnes: without a target list,
its pack shipped the Nintendo DS firmware anyway.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone

import yaml

from . import BaseTargetScraper

PLATFORM_NAME = "amberelec"

RAW_BASE = "https://raw.githubusercontent.com/AmberELEC/AmberELEC/{ref}"
META_MK = "packages/amberelec/package.mk"

try:
    from ..amberelec_scraper import BUILDS_OF, ES_SYSTEMS_TEMPLATE, RUNNERS
    from ..base_scraper import fetch_bytes
    from ..batocera_scraper import _not_cores
    from ..es_emulators import es_cores, xml_systems
except ImportError:
    from scraper.amberelec_scraper import BUILDS_OF, ES_SYSTEMS_TEMPLATE, RUNNERS
    from scraper.base_scraper import fetch_bytes
    from scraper.batocera_scraper import _not_cores
    from scraper.es_emulators import es_cores, xml_systems

_DEVICE_RE = re.compile(
    r"^(\w+):\n\tDEVICE=(\w+) ARCH=(\w+) \./scripts/build_distro$", re.MULTILINE
)
_EXTRA_RE = re.compile(r'LIBRETRO_CORES_EXTRA="([^"]*)"')
# The `if` whose body adds the extra cores to PKG_EMUS.
_EXTRA_IF_RE = re.compile(
    r"if \[\[ (?P<test>[^\n]*?) \]\]; then\s*\n\s*PKG_EMUS\+=\" \$\{LIBRETRO_CORES_EXTRA\}\""
)
# What makeinstall_target does to es_systems.cfg on the other devices.
_REMOVAL_LINES = (
    "for CORE in ${LIBRETRO_CORES_EXTRA}; do",
    'sed -i "s|<core>$CORE</core>||g"',
    r"sed -i -e '/<emulator name/{:a;N;/<\/emulator>/!ba;/melonds/d}'",
)
_EMULATOR_BLOCK_RE = re.compile(r"[^\n]*<emulator name.*?</emulator>[^\n]*\n?", re.DOTALL)


def devices(makefile: str) -> dict[str, str]:
    """{device: architecture} of each image the Makefile builds."""
    found = {device: arch for target, device, arch in _DEVICE_RE.findall(makefile)
             if target == device}
    if not found:
        raise RuntimeError("the AmberELEC Makefile builds no device image")
    return found


def extra_cores(package_mk: str) -> tuple[list[str], set[str]]:
    """(the extra cores, the devices that keep them) from the metapackage."""
    listed = _EXTRA_RE.search(package_mk)
    test = _EXTRA_IF_RE.search(package_mk)
    if listed is None or test is None:
        raise RuntimeError(f"{META_MK}: no LIBRETRO_CORES_EXTRA or no test adding it")
    missing = [line for line in _REMOVAL_LINES if line not in package_mk]
    if missing:
        raise RuntimeError(f"{META_MK}: makeinstall_target no longer reads {missing[0]!r}")
    keep = set(re.findall(r'"\$\{DEVICE\}" == "(\w+)"', test.group("test")))
    for alternatives in re.findall(r'"\$\{DEVICE\}" =~ \^\(([\w|]+)\)\$', test.group("test")):
        keep.update(alternatives.split("|"))
    if not keep:
        raise RuntimeError(f"{META_MK}: the test adding the extra cores names no device")
    return listed.group(1).split(), keep


def without_cores(es_systems: str, cores: list[str]) -> str:
    """es_systems.cfg as makeinstall_target leaves it on a device without them."""
    for core in cores:
        if core == "melonds":
            es_systems = _EMULATOR_BLOCK_RE.sub(
                lambda block: "" if "melonds" in block.group(0) else block.group(0),
                es_systems,
            )
        es_systems = es_systems.replace(f"<core>{core}</core>", "")
    return es_systems


def device_cores(es_systems: str, extra: list[str], keeps_extra: bool) -> list[str]:
    """Every core and standalone emulator one device's es_systems.cfg offers."""
    text = es_systems if keeps_extra else without_cores(es_systems, extra)
    cores, _standalone, _dual = es_cores(
        xml_systems(text), RUNNERS, BUILDS_OF, _not_cores(PLATFORM_NAME)
    )
    return sorted(set(cores))


class Scraper(BaseTargetScraper):
    """Per-device core lists from AmberELEC's metapackage."""

    def __init__(self, url: str = "https://github.com/AmberELEC/AmberELEC") -> None:
        super().__init__(url=url)
        self.ref = ""

    def _raw(self, path: str) -> str:
        return fetch_bytes(f"{RAW_BASE.format(ref=self.ref)}/{path}").decode("utf-8")

    def fetch_targets(self) -> dict:
        self.ref = self.pinned_revision(PLATFORM_NAME)
        extra, keep = extra_cores(self._raw(META_MK))
        es_systems = fetch_bytes(ES_SYSTEMS_TEMPLATE.format(ref=self.ref)).decode("utf-8")
        targets: dict[str, dict] = {}
        for device, arch in sorted(devices(self._raw("Makefile")).items()):
            cores = device_cores(es_systems, extra, device in keep)
            targets[device.lower()] = {"architecture": arch, "cores": cores}
            print(f"  {device.lower()} ({arch}): {len(cores)} cores", file=sys.stderr)
        return {
            "platform": PLATFORM_NAME,
            "source": f"{self.url}/blob/{self.ref}/{META_MK}",
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description="Scrape AmberELEC per-device cores"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = Scraper()
    data = scraper.fetch_targets()
    if args.dry_run:
        for name, info in data["targets"].items():
            print(f"  {name} ({info['architecture']}): {len(info['cores'])} cores")
        return
    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return
    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
