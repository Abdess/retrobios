"""Scraper for ROCKNIX per-device emulator availability.

Sources (ROCKNIX/distribution, at the release tag platforms/rocknix.yml names):
  - projects/ROCKNIX/packages/virtual/emulators/package.mk -- the cores every
    image carries, those aarch64 adds, and a `case "${DEVICE}"` block per SoC
  - projects/ROCKNIX/devices/<DEVICE>/options -- ENABLE_32BIT, which the 32-bit
    cores of a device depend on (distributions/ROCKNIX/options defaults it on)
  - each libretro package's package.mk -- the cores its makeinstall_target
    copies to ${INSTALL}/usr/lib/libretro (vice-lr installs ten of them)

An H700 or RK3326 handheld carries neither Dolphin nor AetherSX2: without a
target list, its pack shipped the PS2, GameCube and PS3 firmware anyway.
"""

from __future__ import annotations

import argparse
import json
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


_INSTALL_BODY_RE = re.compile(r"^makeinstall_target\(\)\s*\{\n(.*?)^\}", re.M | re.S)
_COPY_RE = re.compile(r"\bcp\s+(.*?)\s+\$\{?INSTALL\}?/usr/lib/libretro(?:/(\S*))?")
_CORE_FILE_RE = re.compile(r"([\w+.-]+)_libretro\.(?:so\b|\{[^}]*\bso\b[^}]*\})")
_TEST_RE = re.compile(r'\[\s*"\$\{(\w+)\}"\s*=\s*"([^"]*)"\s*\]')


def installed_cores(package_mk: str, arch: str, with_32bit: bool) -> list[str]:
    """The cores a libretro package installs on a device.

    The name is that of the file makeinstall_target copies to
    ${INSTALL}/usr/lib/libretro ($INSTALL in some), renamed when the copy names its target:
    beetle-psx-lr copies mednafen_psx_libretro.so as beetle_psx_libretro.so,
    vice-lr ten EMUTYPE builds. pcsx_rearmed-lr picks its file by
    TARGET_ARCH and adds the 32-bit build when ENABLE_32BIT is on, desmume-lr
    copies the 32-bit build on aarch64 (ARCH). A test on another variable,
    or a package that installs no core, is an error.
    """
    body = _INSTALL_BODY_RE.search(package_mk)
    if body is None:
        raise RuntimeError("package.mk has no makeinstall_target")
    # config/options:36 sets TARGET_ARCH="${ARCH}".
    values = {"ARCH": arch, "TARGET_ARCH": arch, "ENABLE_32BIT": "true" if with_32bit else "false"}

    def holds(condition: str) -> bool:
        tests = _TEST_RE.findall(condition)
        if not tests or re.sub(_TEST_RE, "", condition).strip(" ;&") not in ("", "then"):
            raise RuntimeError(f"makeinstall_target tests {condition.strip()!r}")
        for variable, value in tests:
            if variable not in values:
                raise RuntimeError(f"makeinstall_target tests ${{{variable}}}")
            if values[variable] != value:
                return False
        return True

    found: list[str] = []
    stack: list[bool] = []
    in_case = False
    for raw in body.group(1).splitlines():
        line = raw.strip()
        if re.match(r"case \$\{TARGET_ARCH\} in$", line):
            in_case = True
            stack.append(False)
            continue
        if line == "esac":
            in_case = False
            stack.pop()
            continue
        if in_case and (arm := re.match(r"([\w|*]+)\)\s*(.*)$", line)):
            stack[-1] = arch in arm.group(1).split("|") or arm.group(1) == "*"
            line = arm.group(2)
        if line.startswith("if "):
            stack.append(holds(line[3:]))
            continue
        if line == "else":
            stack[-1] = not stack[-1]
            continue
        if line == "fi":
            stack.pop()
            continue
        if not all(stack):
            continue
        for sources, target in _COPY_RE.findall(line):
            if named := _CORE_FILE_RE.search(target):
                found.append(named.group(1))
                continue
            for source in sources.split():
                if not source.startswith("-") and (named := _CORE_FILE_RE.search(source.rsplit("/", 1)[-1])):
                    found.append(named.group(1))
    if not found:
        raise RuntimeError("makeinstall_target installs no libretro core")
    return sorted(set(found))


def package_paths(tree: list[str]) -> dict[str, str]:
    """package name -> its package.mk, a ROCKNIX project package first.

    The build takes projects/ROCKNIX/packages/<...>/<name> over
    packages/<...>/<name> when both exist.
    """
    found: dict[str, str] = {}
    for path in sorted(tree, key=lambda p: not p.startswith("projects/ROCKNIX/")):
        if path.endswith("/package.mk"):
            found.setdefault(path.rsplit("/", 2)[-2], path)
    return found


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

    def _tree(self) -> list[str]:
        listing = json.loads(fetch_bytes(
            f"https://api.github.com/repos/ROCKNIX/distribution/git/trees/{self.tag}?recursive=1",
            headers=github_headers(),
        ))
        if listing.get("truncated"):
            raise RuntimeError(f"ROCKNIX tree at {self.tag} is truncated")
        return [entry["path"] for entry in listing.get("tree", [])]

    def device_builds(self, tag: str | None = None) -> dict[str, tuple[str, list[str], list[str]]]:
        """{device: (architecture, libretro cores, standalone packages)}.

        Read at `tag`, by default the revision platforms/rocknix.yml was
        scraped at: metapackages resolved to the packages they pull in, and
        each libretro package to the cores it installs on the device.
        """
        self.tag = tag or self.pinned_revision(PLATFORM_NAME)
        package_mk = self._raw(EMULATORS_MK)
        if "LIBRETRO_CORES" not in package_mk:
            raise RuntimeError(f"no LIBRETRO_CORES in {EMULATORS_MK} at {self.tag}")
        paths = package_paths(self._tree())
        texts: dict[str, str] = {}

        def cores_of(package: str, arch: str, with_32bit: bool) -> list[str]:
            if package not in paths:
                raise RuntimeError(f"no package.mk for {package} at {self.tag}")
            if package not in texts:
                texts[package] = self._raw(paths[package])
            try:
                return installed_cores(texts[package], arch, with_32bit)
            except RuntimeError as e:
                raise RuntimeError(f"{paths[package]}: {e}") from e

        builds: dict[str, tuple[str, list[str], list[str]]] = {}
        for device in self._devices():
            options = self._raw(f"{DEVICES_DIR}/{device}/options")
            arch = "x86_64" if device == "AMD64" else "aarch64"
            with_32bit = not re.search(r'ENABLE_32BIT="false"', options)
            libretro, standalone = parse_device_cores(package_mk, device, arch, with_32bit)
            for meta, path in METAPACKAGES.items():
                if meta in libretro:
                    libretro.remove(meta)
                    libretro += metapackage_cores(self._raw(path), arch)
            cores = sorted({c for package in libretro for c in cores_of(package, arch, with_32bit)})
            builds[device.lower()] = (arch, cores, standalone)
        return builds

    def fetch_targets(self) -> dict:
        targets: dict[str, dict] = {}
        for device, (arch, libretro, standalone) in self.device_builds().items():
            # A standalone package is kept under both spellings, as the
            # platform scraper keeps it: vice-sa is the only name
            # vice-standalone answers to, vice that of the libretro profile.
            cores = sorted({*libretro, *standalone_emulators(standalone)})
            targets[device] = {"architecture": arch, "cores": cores}
            print(f"  {device} ({arch}): {len(cores)} cores", file=sys.stderr)

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
