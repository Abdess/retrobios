#!/usr/bin/env python3
"""Scraper for MinUI and the frontends built on it (NextUI, MyMinUI).

Source: the frontend's repository at a pinned commit
Format: one emulator pak per launch tag, ``skeleton/SYSTEM/<device>/paks/Emus/
<TAG>.pak/launch.sh`` (base install) or ``skeleton/EXTRAS/Emus/<device>/
<TAG>.pak/launch.sh`` (extras bundle), whose script names the libretro core
in ``EMU_EXE`` and starts it under minarch.

None of the three publishes a BIOS list in code: the frontend hands every
core the folder ``<SD>/Bios/<TAG>/`` as its libretro system directory
(``core.bios_dir``, returned for RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY) and
never opens or hashes a BIOS file itself. What the code does state is which
core each tag runs, and that tag decides the folder. So the platform file
carries no file entry: it maps each folder to the cores launched with it,
and the files are the ones the core profiles document, placed below that
folder.

Paks that start a standalone binary (NDS.pak runs DraStic, P8-NATIVE.pak
the PICO-8 executable) set no ``EMU_EXE`` and are not libretro launches:
they are counted and left out.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .base_scraper import (
    BaseScraper,
    BiosRequirement,
    fetch_branch_head,
    fetch_bytes,
    github_headers,
)

PLATFORM_NAME = "minui"


@dataclass(frozen=True)
class Variant:
    """One frontend of the family: where its code lives and what it is called."""

    key: str
    name: str
    repo: str
    branch: str
    homepage: str
    # The file that sets core.bios_dir.
    minarch_source: str


VARIANTS: dict[str, Variant] = {
    "minui": Variant(
        key="minui",
        name="MinUI",
        repo="shauninman/MinUI",
        branch="main",
        homepage="https://github.com/shauninman/MinUI",
        minarch_source="workspace/all/minarch/minarch.c",
    ),
    "nextui": Variant(
        key="nextui",
        name="NextUI",
        repo="LoveRetro/NextUI",
        branch="main",
        homepage="https://nextui.loveretro.games",
        minarch_source="workspace/all/minarch/ma_core.c",
    ),
    "myminui": Variant(
        key="myminui",
        name="MyMinUI",
        repo="Turro75/MyMinUI",
        branch="main",
        homepage="https://github.com/Turro75/MyMinUI",
        minarch_source="workspace/all/minarch/minarch.c",
    ),
}

# The folder minarch hands a core: SDCARD_PATH "/Bios/" and the launch tag.
BIOS_ROOT = "Bios"
_BIOS_DIR = re.compile(
    r'sprintf\(\s*\(char\s*\*\)\s*core\.bios_dir\s*,\s*SDCARD_PATH\s*"/Bios/%s"\s*,\s*core\.tag\s*\)'
)
_PAK = re.compile(
    r"^skeleton/(?:SYSTEM/(?P<base>[^/]+)/paks/Emus|EXTRAS/Emus/(?P<extra>[^/]+))"
    r"/(?P<tag>[^/]+)\.pak/launch\.sh$"
)
_EMU_EXE = re.compile(r"^[ \t]*EMU_EXE=([A-Za-z0-9_.-]+)[ \t]*$", re.MULTILINE)
# Both ways a pak starts its core: minarch on the core's .so directly, or
# MyMinUI's launch_rom.sh, which runs minarch (or RetroArch with
# system_directory set to the same folder) on ${EMU_EXE}_libretro.so.
_STARTS_CORE = re.compile(
    r'^[ \t]*(?:nice\s+-?\d+\s+)?minarch\.elf\s+"\$CORES_PATH/\$\{EMU_EXE\}_libretro\.so"'
    r"|^[ \t]*launch_rom\.sh\s",
    re.MULTILINE,
)
# Each device builds its cores from workspace/<device>/cores/makefile through
# the template in workspace/all/cores/makefile: `<X>_REPO ?=
# https://github.com/libretro/<X>` and the library `<X>_libretro.so` unless
# `<X>_CORE` names another.
_RECIPE = re.compile(r"^workspace/(?P<device>[^/]+)/cores/makefile$")
_CORES_LIST = re.compile(r"^CORES\s*\+?=(.*)$", re.MULTILINE)
_CORE_VAR = re.compile(r"^(\S+?)_(REPO|CORE)\s*\??=\s*(\S+)", re.MULTILINE)
# A library built from a project other than the libretro core of that name:
# MyMinUI builds dosbox-pure into dosbox_libretro.so. The core is the project
# the bytes come from.
BUILT_AS = {
    "https://github.com/libretro/dosbox-pure": "dosbox_pure",
}


@dataclass(frozen=True)
class Pak:
    """One emulator pak as its launch script states it."""

    tag: str
    device: str
    core: str
    path: str
    line: int


def read_pak(path: str, text: str) -> Pak | None:
    """The libretro launch a pak's script makes, or None for a standalone one.

    A script that names a core but starts it in a way not read here raises:
    the shape of the paks changed and the scrape must say so.
    """
    match = _PAK.match(path)
    if not match:
        return None
    exe = _EMU_EXE.search(text)
    if not exe:
        return None
    if not _STARTS_CORE.search(text):
        raise ValueError(f"{path}: EMU_EXE={exe.group(1)} but no minarch launch")
    line = text.count("\n", 0, exe.start()) + 1
    return Pak(
        tag=match.group("tag"),
        device=match.group("base") or match.group("extra"),
        core=exe.group(1),
        path=path,
        line=line,
    )


def normalize_repository(url: str) -> str:
    """A repository URL without the .git suffix or a trailing slash."""
    url = url.strip().rstrip("/")
    return url[: -len(".git")] if url.endswith(".git") else url


def read_recipes(text: str) -> dict[str, str]:
    """Library file name to source repository, for one device's core makefile."""
    text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    names = [name for match in _CORES_LIST.finditer(text) for name in match.group(1).split()]
    values: dict[tuple[str, str], str] = {
        (match.group(1), match.group(2)): match.group(3) for match in _CORE_VAR.finditer(text)
    }
    return {
        values.get((name, "CORE"), f"{name}_libretro.so"): normalize_repository(
            values.get((name, "REPO"), f"https://github.com/libretro/{name}")
        )
        for name in names
    }


def bios_dir_ref(source: str, text: str) -> str:
    """``file:line`` of the statement that sets the per-tag system directory."""
    match = _BIOS_DIR.search(text)
    if not match:
        raise ValueError(f"{source}: core.bios_dir is no longer SDCARD_PATH/Bios/<tag>")
    return f"{source}:{text.count(chr(10), 0, match.start()) + 1}"


def core_identity(library: str, repositories: Mapping[str, set[str]]) -> str:
    """The core a pak's library is, by the project it is built from."""
    stem = library.removesuffix("_libretro.so")
    built = sorted({BUILT_AS[r] for r in repositories.get(library, set()) if r in BUILT_AS})
    if len(built) > 1:
        raise ValueError(f"{library} is built from projects of {', '.join(built)}")
    return built[0] if built else stem


def core_system_dirs(
    paks: list[Pak], repositories: Mapping[str, set[str]] | None = None
) -> dict[str, dict]:
    """Each Bios/<TAG> folder with the cores its paks run and where they ship."""
    repositories = repositories or {}
    by_dir: dict[str, dict] = {}
    for pak in sorted(paks, key=lambda p: (p.tag, p.device, p.path)):
        entry = by_dir.setdefault(
            f"{BIOS_ROOT}/{pak.tag}",
            {"cores": [], "devices": [], "source_ref": f"{pak.path}:{pak.line}"},
        )
        core = core_identity(f"{pak.core}_libretro.so", repositories)
        if core not in entry["cores"]:
            entry["cores"].append(core)
        if pak.device not in entry["devices"]:
            entry["devices"].append(pak.device)
    for entry in by_dir.values():
        entry["cores"].sort()
        entry["devices"].sort()
    return dict(sorted(by_dir.items()))


def platform_config(
    variant: Variant, revision: str, date: str, files: Mapping[str, str]
) -> dict:
    """The platform file for one frontend, from its sources at ``revision``.

    ``files`` maps repository paths to their text: every pak launch script,
    every device's core makefile and the minarch source that sets the
    system directory.
    """
    if variant.minarch_source not in files:
        raise ValueError(f"{variant.repo}@{revision}: no {variant.minarch_source}")
    reference = bios_dir_ref(variant.minarch_source, files[variant.minarch_source])
    paks = [pak for path, text in sorted(files.items()) if (pak := read_pak(path, text))]
    if not paks:
        raise ValueError(f"{variant.repo}@{revision}: no pak starts a libretro core")
    repositories: dict[str, set[str]] = {}
    for path, text in files.items():
        if _RECIPE.match(path):
            for library, repository in read_recipes(text).items():
                repositories.setdefault(library, set()).add(repository)
    dirs = core_system_dirs(paks, repositories)
    built_from = {
        core_identity(f"{pak.core}_libretro.so", repositories): sorted(
            repositories.get(f"{pak.core}_libretro.so", set())
        )
        for pak in paks
    }
    return {
        "platform": variant.name,
        "version": date,
        "homepage": variant.homepage,
        "source": f"https://github.com/{variant.repo}/tree/{revision}",
        # The card root: every core reads below Bios/<TAG>/ on it.
        "base_destination": "",
        "hash_type": "sha1",
        # minarch hands the folder and never reads or hashes a file in it.
        "verification_mode": "existence",
        "system_directory_ref": reference,
        "cores": sorted({core for entry in dirs.values() for core in entry["cores"]}),
        "core_system_dirs": dirs,
        # Where each core's library is built from, read from the device
        # makefiles. A pak may ship a library no makefile builds.
        "core_repositories": {core: repos for core, repos in sorted(built_from.items()) if repos},
        "systems": {},
    }


class Scraper(BaseScraper):
    """Pak scraper for one frontend of the MinUI family."""

    lists_files = False
    variant: Variant = VARIANTS["minui"]

    def __init__(
        self,
        url: str | None = None,
        fetch: Callable[[str, dict[str, str] | None], bytes] | None = None,
    ) -> None:
        self._fetch = fetch or (lambda u, h=None: fetch_bytes(u, headers=h))
        self.revision = ""
        if url is None:
            self.revision = fetch_branch_head(self.variant.repo, self.variant.branch)
            url = f"https://github.com/{self.variant.repo}/tree/{self.revision}"
        super().__init__(url=url)
        self._config: dict | None = None

    def _api(self, path: str) -> dict:
        url = f"https://api.github.com/repos/{self.variant.repo}/{path}"
        try:
            return json.loads(self._fetch(url, github_headers()))
        except (ConnectionError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot read {url}: {exc}") from exc

    def _raw(self, path: str) -> str:
        url = (
            f"https://raw.githubusercontent.com/{self.variant.repo}/{self.revision}/"
            f"{urllib.parse.quote(path)}"
        )
        return self._fetch(url, None).decode("utf-8", errors="replace")

    def config(self) -> dict:
        """The platform file, read once."""
        if self._config is not None:
            return self._config
        if not self.revision:
            self.revision = self.url.rstrip("/").rsplit("/", 1)[-1]
        tree = self._api(f"git/trees/{self.revision}?recursive=1")
        if tree.get("truncated"):
            raise RuntimeError(f"{self.variant.repo}@{self.revision}: tree listing truncated")
        paths = [
            item["path"] for item in tree.get("tree", [])
            if item.get("type") == "blob"
            and (
                _PAK.match(item["path"])
                or _RECIPE.match(item["path"])
                or item["path"] == self.variant.minarch_source
            )
        ]
        commit = self._api(f"commits/{self.revision}")
        date = commit.get("commit", {}).get("committer", {}).get("date", "")[:10]
        if not date:
            raise RuntimeError(f"{self.variant.repo}@{self.revision}: commit has no date")
        files = {path: self._raw(path) for path in paths}
        self._config = platform_config(self.variant, self.revision, date, files)
        return self._config

    def fetch_requirements(self) -> list[BiosRequirement]:
        """None: the frontend names no BIOS file in code, its cores do."""
        self.config()
        return []

    def validate_format(self, raw_data: str) -> bool:
        return bool(self.config().get("core_system_dirs"))

    def generate_platform_yaml(self) -> dict:
        return self.config()


def main() -> None:
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape the MinUI pak list")


if __name__ == "__main__":
    main()
