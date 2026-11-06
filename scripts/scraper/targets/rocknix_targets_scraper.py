"""Scraper for ROCKNIX per-device emulator availability.

Sources (ROCKNIX/distribution, at the release tag platforms/rocknix.yml names):
  - projects/ROCKNIX/packages/virtual/emulators/package.mk -- the cores every
    image carries, those aarch64 adds, and a `case "${DEVICE}"` block per SoC
  - projects/ROCKNIX/devices/<DEVICE>/options -- ENABLE_32BIT, which the 32-bit
    cores of a device depend on (distributions/ROCKNIX/options defaults it on)

An H700 or RK3326 handheld carries neither Dolphin nor AetherSX2: without a
target list, its pack shipped the PS2, GameCube and PS3 firmware anyway.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone

import yaml

from . import BaseTargetScraper

PLATFORM_NAME = "rocknix"

RAW_BASE = "https://raw.githubusercontent.com/ROCKNIX/distribution/{tag}"
GITHUB_API = "https://api.github.com/repos/ROCKNIX/distribution/contents"
EMULATORS_MK = "projects/ROCKNIX/packages/virtual/emulators/package.mk"
DEVICES_DIR = "projects/ROCKNIX/devices"

try:
    from ..base_scraper import fetch_bytes, github_headers
    from ..rocknix_scraper import standalone_emulators
except ImportError:
    from scraper.base_scraper import fetch_bytes, github_headers
    from scraper.rocknix_scraper import standalone_emulators

# `NAME="a b \
#   c"` or `NAME+=" a b"`, continuation lines joined first.
_ASSIGN_RE = re.compile(r'^\s*(?:\[[^\]]*\]\s*&&\s*)?(\w+)(\+?=)"([^"]*)"', re.MULTILINE)
_CASE_RE = re.compile(r'case "\$\{DEVICE\}" in(.*?)\besac\b', re.DOTALL)
_ARM_RE = re.compile(r"^\s*([A-Z0-9|]+)\)\s*$", re.MULTILINE)
_AARCH64_RE = re.compile(
    r'if \[ "\$\{ARCH\}" = "aarch64" \]; then(.*?)\bfi\b', re.DOTALL
)


def _assignments(text: str) -> list[tuple[str, str, list[str]]]:
    """(variable, operator, words) of each quoted assignment, in order."""
    joined = re.sub(r"\\\n", " ", text)
    return [(name, op, value.split()) for name, op, value in _ASSIGN_RE.findall(joined)]


def _apply(state: dict[str, list[str]], text: str, with_32bit: bool) -> None:
    for name, op, words in _assignments(text):
        if name == "EMUS_32BIT" and not with_32bit:
            continue
        if op == "=":
            state[name] = list(words)
        else:
            state.setdefault(name, []).extend(words)


def parse_device_cores(
    package_mk: str, device: str, arch: str, with_32bit: bool
) -> tuple[list[str], list[str]]:
    """(libretro packages, standalone packages) one device's image carries."""
    case = _CASE_RE.search(package_mk)
    head = package_mk[: case.start()] if case else package_mk
    aarch64 = _AARCH64_RE.search(head)
    base = head if aarch64 is None else head[: aarch64.start()] + head[aarch64.end():]
    state: dict[str, list[str]] = {}
    _apply(state, base, with_32bit)
    if arch == "aarch64" and aarch64 is not None:
        _apply(state, aarch64.group(1), with_32bit)
    if case is not None:
        arms = list(_ARM_RE.finditer(case.group(1)))
        for index, arm in enumerate(arms):
            if device not in arm.group(1).split("|"):
                continue
            end = arms[index + 1].start() if index + 1 < len(arms) else len(case.group(1))
            _apply(state, case.group(1)[arm.end():end], with_32bit)
    libretro = state.get("LIBRETRO_CORES", []) + [
        p for p in state.get("EMUS_32BIT", []) if re.search(r"[-_]lr$", p)
    ]
    standalone = state.get("PKG_EMUS", []) + [
        p for p in state.get("EMUS_32BIT", []) if not re.search(r"[-_]lr$", p)
    ]
    return libretro, standalone


def core_names(libretro: list[str], standalone: list[str]) -> list[str]:
    """Package names as the profiles' cores: lists spell them.

    A libretro package is the core's name with `-lr` (`beetle-psx-lr`,
    `neocd_lr`), spelled with underscores as the buildbot names it. A
    standalone package is kept under both spellings, as the platform
    scraper keeps it: `vice-sa` is the only name vice-standalone answers
    to, `vice` that of the libretro profile.
    """
    names = {re.sub(r"[-_]lr$", "", package).replace("-", "_") for package in libretro}
    names.update(standalone_emulators(standalone))
    return sorted(names)


# A package that builds nothing itself and pulls other cores in. idtech-lr
# installs ecwolf, prboom, tyrquake and vitaquake2 (vitaquake3 and boom3 on
# x86_64). No profile could name it.
METAPACKAGES = {"idtech-lr": "projects/ROCKNIX/packages/emulators/libretro/idtech-lr/package.mk"}
_IF_RE = re.compile(r'^if \[ "\$\{(\w+)\}" = "?([\w-]+)"? \]; then\n(.*?)^fi$',
                    re.MULTILINE | re.DOTALL)


def metapackage_cores(package_mk: str, arch: str) -> list[str]:
    """The -lr packages a metapackage depends on for one architecture.

    OPENGLES_SUPPORT is yes on every ROCKNIX device (config/graphic, from
    OPENGLES="mesa" in projects/ROCKNIX/options), and TARGET_ARCH is the device's.
    """
    found: list[str] = []
    for variable, value, body in _IF_RE.findall(package_mk):
        if variable == "TARGET_ARCH" and value != arch:
            continue
        if variable not in ("TARGET_ARCH", "OPENGLES_SUPPORT"):
            continue
        for _name, _op, words in _assignments(body):
            found += [w for w in words if re.search(r"[-_]lr$", w)]
    return found


class Scraper(BaseTargetScraper):
    """Per-device core lists from ROCKNIX's emulators metapackage."""

    def __init__(self, url: str = "https://github.com/ROCKNIX/distribution") -> None:
        super().__init__(url=url)
        self.tag = ""

    def _raw(self, path: str) -> str:
        return fetch_bytes(f"{RAW_BASE.format(tag=self.tag)}/{path}").decode("utf-8")

    def _devices(self) -> list[str]:
        import json  # noqa: PLC0415

        listing = json.loads(fetch_bytes(
            f"{GITHUB_API}/{DEVICES_DIR}?ref={self.tag}", headers=github_headers()
        ))
        devices = [item["name"] for item in listing if item.get("type") == "dir"]
        if not devices:
            raise RuntimeError(f"no device in {DEVICES_DIR} at {self.tag}")
        return sorted(devices)

    def fetch_targets(self) -> dict:
        self.tag = self.pinned_revision(PLATFORM_NAME)
        package_mk = self._raw(EMULATORS_MK)
        if "LIBRETRO_CORES" not in package_mk:
            raise RuntimeError(f"no LIBRETRO_CORES in {EMULATORS_MK} at {self.tag}")

        targets: dict[str, dict] = {}
        for device in self._devices():
            options = self._raw(f"{DEVICES_DIR}/{device}/options")
            arch = "x86_64" if device == "AMD64" else "aarch64"
            with_32bit = not re.search(r'ENABLE_32BIT="false"', options)
            libretro, standalone = parse_device_cores(package_mk, device, arch, with_32bit)
            for meta, path in METAPACKAGES.items():
                if meta in libretro:
                    libretro.remove(meta)
                    libretro += metapackage_cores(self._raw(path), arch)
            cores = core_names(libretro, standalone)
            targets[device.lower()] = {"architecture": arch, "cores": cores}
            print(f"  {device.lower()} ({arch}): {len(cores)} cores", file=sys.stderr)

        return {
            "platform": PLATFORM_NAME,
            "source": f"{self.url}/tree/{self.tag}/{EMULATORS_MK}",
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Scrape ROCKNIX per-device cores")
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
