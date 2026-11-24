"""Where a campaign's cores come from: the buildbot nightly, else a sandboxed build of the profile's pinned commit."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

import core_probe
from core.hashing import file_digest
from core.statefile import now_iso
from probes.host import NETWORK_DELAYS, Unavailable, child_env, run_group, slug

if TYPE_CHECKING:
    from probes.checkruns import CheckRuns


T = TypeVar("T")


BUILDBOT = "https://buildbot.libretro.com/nightly/linux/x86_64/latest/"


BUILD_TIMEOUT = 3600


# Host-side git on a third-party project. It only ever touches bare mirrors
# this campaign created: no working tree, never bound into a sandbox. No user
# or system config is read, https is the only transport, and the overrides
# blank every hook, filter, proxy and ssh command a config could name.
GIT_SAFE = (
    "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
    "-c", "core.sshCommand=", "-c", "core.gitProxy=", "-c", "core.askPass=",
    "-c", "credential.helper=", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
    "-c", "filter.lfs.smudge=", "-c", "filter.lfs.clean=", "-c", "filter.lfs.process=",
    "-c", "filter.lfs.required=false", "-c", "core.attributesFile=/dev/null",
)
MIRROR_URL = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d+)?/[A-Za-z0-9._~/+-]+$")


def host_git(*args: str) -> list[str]:
    return ["git", *GIT_SAFE, *args]


def git_env() -> dict[str, str]:
    env = child_env()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_ALLOW_PROTOCOL="https", GIT_ATTR_NOSYSTEM="1")
    return env


def blank_filters(repo: Path) -> list[str]:
    """-c overrides emptying every filter driver the repository's config,
    includes followed, defines: git archive runs smudge filters."""
    config = repo / "config"
    if not config.is_file():
        return []
    listing = run_group(["git", "config", "--file", str(config), "--includes", "--name-only",
                         "--get-regexp", r"^filter\."], capture_output=True, env=git_env(),
                        timeout=60).stdout.decode("utf-8", "replace")
    drivers = sorted({line.rsplit(".", 1)[0] for line in listing.splitlines() if line.count(".") >= 2})
    out = []
    for driver in drivers:
        for key in ("smudge", "clean", "process"):
            out += ["-c", f"{driver}.{key}="]
        out += ["-c", f"{driver}.required=false"]
    return out


def git_out(*args: str, timeout: int = 1800) -> bytes:
    extra = blank_filters(Path(args[1])) if len(args) > 1 and args[0] == "-C" else []
    return run_group(["git", *GIT_SAFE, *extra, *args], capture_output=True, check=True,
                     env=git_env(), timeout=timeout).stdout


def submodule_url(base: str, url: str) -> str:
    """A .gitmodules URL, relative ones read against the parent's URL."""
    if url.startswith(("./", "../")):
        parts = base.rstrip("/").removesuffix(".git").split("/")
        for piece in url.split("/"):
            if piece == "..":
                parts.pop()
            elif piece not in (".", ""):
                parts.append(piece)
        url = "/".join(parts)
    return url


def extract_tar(blob: bytes, target: Path) -> None:
    """A git archive unpacked into target: no absolute path, no .., no link
    that leaves target."""
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob)) as handle:
        if hasattr(tarfile, "data_filter"):
            handle.extractall(target, filter="data")
            return
        for member in handle.getmembers():
            name = Path(member.name)
            link = Path(member.linkname)
            if name.is_absolute() or ".." in name.parts or member.islnk() or (
                    member.issym() and (link.is_absolute() or ".." in link.parts)):
                raise Unavailable(f"core: unsafe archive member {member.name}")
        handle.extractall(target)


def export_commit(mirror: Callable[[str], Path], url: str, commit: str, dest: Path) -> None:
    """The tree of commit, and of each submodule at the commit the tree
    records, as plain files in a fresh dest. Every object comes from a bare
    mirror (mirror(url) fetches into it), never from a working tree."""
    if dest.exists():
        shutil.rmtree(dest)

    def one(repo_url: str, sha: str, target: Path) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise Unavailable(f"core: {sha!r} is not a commit id")
        bare = mirror(repo_url)
        try:
            git_out("-C", str(bare), "cat-file", "-e", f"{sha}^{{commit}}")
        except subprocess.CalledProcessError:
            git_out("-C", str(bare), "fetch", "--quiet", repo_url, sha)
        extract_tar(git_out("-C", str(bare), "archive", "--format=tar", sha), target)
        links: dict[str, str] = {}
        for entry in git_out("-C", str(bare), "ls-tree", "-r", "-z", sha).split(b"\0"):
            if entry.startswith(b"160000 commit "):
                meta, raw_path = entry.split(b"\t", 1)
                links[raw_path.decode()] = meta.split()[2].decode()
        if not links:
            return
        try:
            config = git_out("-C", str(bare), "config", "--blob", f"{sha}:.gitmodules", "-z",
                             "--get-regexp", r"^submodule\..*\.(path|url)$").decode()
        except subprocess.CalledProcessError as exc:
            raise Unavailable(f"core: {repo_url} has submodules and no readable .gitmodules") from exc
        paths: dict[str, str] = {}
        urls: dict[str, str] = {}
        for item in filter(None, config.split("\0")):
            key, _, value = item.partition("\n")
            name, field_ = key[len("submodule."):].rsplit(".", 1)
            (paths if field_ == "path" else urls)[name] = value
        for name, path in paths.items():
            if path in links and name in urls:
                one(submodule_url(repo_url, urls[name]), links[path], target / path)

    one(url, commit, dest)


def built_core(tree: Path) -> Path:
    """The newest *_libretro.so a build left: a regular file inside the tree,
    never a link a build could point at a host file."""
    root = tree.resolve()
    found = []
    for path in tree.rglob("*_libretro.so"):
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and path.resolve().is_relative_to(root):
            found.append((info.st_mtime, path))
    if not found:
        raise Unavailable(f"core: the build left no *_libretro.so regular file in {tree}")
    return max(found)[1]


def copy_regular(src: Path, dest: Path) -> None:
    """Copy src only when it is a regular file, never through a link."""
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise Unavailable(f"core: {src} is not a regular file")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("wb") as out:
            shutil.copyfileobj(handle, out)


# --------------------------------------------------------------------------
# Cores
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Core:
    name: str
    path: Path
    sha256: str
    artifact: str | None = None
    repo: str | None = None
    commit: str | None = None
    build_command: str | None = None


def safe_extract_so(archive: Path, member: str, target: Path) -> None:
    with zipfile.ZipFile(archive) as handle:
        names = handle.namelist()
        if member not in names:
            raise Unavailable(f"{archive.name}: no {member} inside ({', '.join(names[:5])})")
        target.parent.mkdir(parents=True, exist_ok=True)
        scratch = target.with_suffix(".part")
        with handle.open(member) as src, scratch.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        os.replace(scratch, target)


def retrying(what: str, call: Callable[[], T], *, delays: Sequence[float],
             sleep: Callable[[float], None], log: Callable[[str], None]) -> T:
    """call, run again after each delay on a network failure. A client error
    other than 429 is final."""
    for attempt, delay in enumerate((*delays, None)):
        try:
            return call()
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if isinstance(exc, urllib.error.HTTPError) and exc.code < 500 and exc.code != 429:
                raise Unavailable(f"{what}: HTTP {exc.code}") from exc
            if delay is None:
                raise Unavailable(f"{what}: {exc}") from exc
            log(f"{what}: {exc}, retry {attempt + 1} in {delay}s")
            sleep(delay)
    raise AssertionError("unreachable")


def buildbot_listing(urlopen: Callable[..., Any] = urllib.request.urlopen) -> set[str]:
    """The core names the buildbot publishes a nightly of."""
    with urlopen(BUILDBOT, timeout=120) as response:
        page = response.read().decode("utf-8", "replace")
    return set(re.findall(r"([A-Za-z0-9_]+)_libretro\.so\.zip", page))


def fetch_nightly(name: str, target: Path, cached: dict, *, urlopen: Callable[..., Any],
                  retry: Callable[[str, Callable[[], Any]], Any]) -> dict:
    """The buildbot nightly of a core at target, downloaded again when the
    buildbot's ETag or Last-Modified moved or the file on disk is not the one
    cached describes. Returns the record of the file now at target: cached
    itself when nothing changed."""
    url = f"{BUILDBOT}{name}_libretro.so.zip"

    def head() -> dict:
        request = urllib.request.Request(url, method="HEAD")
        with urlopen(request, timeout=120) as response:
            return {"etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified")}
    stamp = retry(f"{name} nightly", head)
    if (cached.get("etag"), cached.get("last_modified")) == (stamp["etag"], stamp["last_modified"]) \
            and target.is_file() and file_digest(target, "sha256") == cached.get("sha256"):
        return cached
    archive = target.parent / f"{name}_libretro.so.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)

    def download() -> None:
        with urlopen(url, timeout=600) as response, archive.open("wb") as out:
            shutil.copyfileobj(response, out)
    retry(f"{name} nightly", download)
    safe_extract_so(archive, f"{name}_libretro.so", target)
    archive.unlink()
    return {**stamp, "url": url, "sha256": file_digest(target, "sha256"), "fetched_at": now_iso()}


def cached_nightly(name: str, folder: Path, *, check: bool = True) -> dict:
    """fetch_nightly for a tool without campaign state, its record kept in
    folder/build.json. Without check, a file on disk that matches its record
    is returned without asking the buildbot."""
    target, record_path = folder / f"{name}_libretro.so", folder / "build.json"
    cached: dict = {}
    if record_path.is_file():
        cached = json.loads(record_path.read_text(encoding="utf-8"))
    if not check and target.is_file() and cached.get("sha256") == file_digest(target, "sha256"):
        return {**cached, "path": str(target)}

    def report(line: str) -> None:
        print(line, file=sys.stderr)

    def retry(what: str, call: Callable[[], Any]) -> Any:
        return retrying(what, call, delays=NETWORK_DELAYS, sleep=time.sleep, log=report)
    record = fetch_nightly(name, target, cached, urlopen=urllib.request.urlopen, retry=retry)
    if record is not cached:
        record = {"name": name, **record}
        record_path.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    return {**record, "path": str(target)}


class Cores:
    """Buildbot nightlies, downloaded once per build, else local builds of
    the profile's pinned commit."""

    def __init__(self, campaign: CheckRuns) -> None:
        self.c = campaign
        self.listing: set[str] | None = None

    def retrying(self, what: str, call: Callable[[], T]) -> T:
        return retrying(what, call, delays=self.c.settings.delays, sleep=self.c.host.sleep, log=self.c.log)

    def buildbot(self) -> set[str]:
        if self.listing is None:
            if not self.c.settings.network:
                self.listing = set()
            else:
                self.listing = self.retrying("buildbot listing", lambda: buildbot_listing(self.c.host.urlopen))
        return self.listing

    def names(self, profile: dict) -> list[str]:
        listing = self.buildbot()
        return sorted({str(c) for c in profile.get("cores") or () if str(c) in listing})

    def nightly(self, name: str, profile: dict) -> Core:
        cached = self.c.state["cores"].get(name) or {}
        target = self.c.paths.home / "cores" / name / f"{name}_libretro.so"
        record = fetch_nightly(name, target, cached, urlopen=self.c.host.urlopen, retry=self.retrying)
        if record is not cached:
            self.c.state["cores"][name] = record
            self.c.log(f"core {name}: new nightly {record['sha256'][:12]} ({record['last_modified']})")
        repo = profile.get("source") if isinstance(profile.get("source"), str) else None
        return Core(name, target, record["sha256"], artifact=record["url"],
                    repo=repo if repo and repo.startswith("http") else None)

    def build(self, emulator: str, profile: dict) -> Core:
        """The profile's pinned commit, built once and kept."""
        source, commit = profile.get("source"), profile.get("source_commit")
        if not (isinstance(source, str) and source.startswith("http") and isinstance(commit, str)):
            raise Unavailable("core: not on the buildbot, and no source and source_commit to build")
        record = self.c.state["builds"].setdefault(emulator, {})
        if record.get("commit") == commit and record.get("error"):
            raise Unavailable(f"core: build of {commit[:12]} failed before: {record['error']}")
        out = self.c.paths.home / "builds" / emulator / commit
        built = sorted(out.glob("*_libretro.so"))
        if not built:
            if not self.c.settings.network:
                raise Unavailable("core: not on the buildbot, offline, nothing built yet")
            try:
                so, command = self.compile(source, commit, out)
            except Unavailable as exc:
                self.c.state["builds"][emulator] = {"commit": commit, "error": str(exc), "at": now_iso()}
                raise
            built = [so]
            record["command"] = command
        command = record.get("command") or "make"
        self.c.state["builds"][emulator] = {"commit": commit, "command": command,
                                            "so": built[0].name, "at": now_iso()}
        return Core(built[0].name.removesuffix("_libretro.so"), built[0], file_digest(built[0], "sha256"),
                    repo=source, commit=commit, build_command=command)

    def mirror(self, url: str) -> Path:
        """The bare mirror of a repository, created on first use. Only host
        git with the overrides of GIT_SAFE ever touches it."""
        if not MIRROR_URL.match(url):
            raise Unavailable(f"core: {url!r} is not an https repository URL")
        bare = self.c.paths.home / "mirrors" / f"{slug(url)}.git"
        if not (bare / "HEAD").is_file():
            bare.parent.mkdir(parents=True, exist_ok=True)
            git_out("clone", "--bare", "--quiet", url, str(bare))
        return bare

    def compile(self, source: str, commit: str, out: Path) -> tuple[Path, str]:
        """Fetch the commit into a bare mirror (host git, networked), export
        it and its submodules with git archive into a fresh folder, and run
        the project's make there under bubblewrap: no network, that folder
        the one writable path. Returns the .so and the command, with how it
        was isolated."""
        log = self.c.paths.logs / "builds" / f"{slug(source)}-{commit[:12]}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        isolation = core_probe.sandbox_argv([])[1]
        if isolation != core_probe.SANDBOX and not self.c.settings.allow_unsandboxed:
            raise Unavailable(f"refused: no sandbox to build {source} in ({isolation}), "
                              f"--allow-unsandboxed overrides")
        # Working-tree clones of earlier campaign versions are never reused.
        shutil.rmtree(self.c.paths.home / "src", ignore_errors=True)
        tree = self.c.paths.home / "build-trees" / f"{slug(source)}-{commit[:12]}"
        try:
            export_commit(self.mirror, source, commit, tree)
        except (OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
            raise Unavailable(f"core: exporting {commit[:12]} of {source} failed: {exc}") from exc
        makefile = "Makefile.libretro" if (tree / "Makefile.libretro").is_file() else "Makefile"
        jobs = str(max(1, (os.cpu_count() or 2) // 2))
        command = ["make", "-f", makefile, f"-j{jobs}", "platform=unix"]
        prefix, isolation = core_probe.sandbox_argv([tree])
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {' '.join(command)} in {tree} ({isolation})\n")
            handle.flush()
            proc = self.c.host.run(prefix + command, cwd=tree, stdout=handle, stderr=subprocess.STDOUT,
                                   check=False, timeout=BUILD_TIMEOUT, env=child_env())
        if proc.returncode != 0:
            tail = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-3:]
            raise Unavailable(f"core: make exited {proc.returncode}: {' | '.join(tail)} (log {log})")
        built = built_core(tree)
        copy_regular(built, out / built.name)
        shutil.rmtree(tree, ignore_errors=True)
        return out / built.name, f"{' '.join(command)} on git archive (isolation: {isolation})"
