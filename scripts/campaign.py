#!/usr/bin/env python3
"""Run the real-condition campaign end to end: cores, content, checks, rules.

A maintainer starts each pass. For each emulator profile in scope, the
campaign takes the core (the libretro x86_64 Linux nightly, else a build of
the profile's pinned commit), the test content of each of its systems
(tests/campaign/content.yml, fetched through romfetch when it is not on
disk), and runs core_probe.py. The boot oracle of core_probe judges every
run: boots, bios_error, crash, hang or unknown, against the reference frames
and error patterns of tests/campaign/oracle.yml.

  files      every declared file the collection holds, staged: the full set,
             and which files the core opens
  none       no BIOS at all
  negative   per declared file of the content's region: the file alone, then
             zeros of its size, its first half and other regions' dumps
             staged under its name
  path       a declared file staged where the core looked for it
  alias      a declared file staged under a name the core looked for
  variants   each .variants/ copy of a file the core opened
  bench      with --bench only: the content timed, warm-up excluded

Every run is a record in measurements/<emulator>.jsonl. The fixed rule table
(campaign_rules.py) reads the verdicts, never a comparison of frames. A
verdict the table settles is written into the profile with the record ids
as `evidence:`. Any other goes to measurements/findings.jsonl, where the
site lists it as open. Each pass adds one line to
measurements/campaign-runs.jsonl.

`review` closes an open finding once a maintainer has read the core's code:
`applied` writes the fields it names through the same profile editor, with
the finding's record ids as `evidence:`, and `rejected` keeps the profile.
The reason, with its file:line, goes on the finding's line, and a rejected
finding stays closed while the runs keep showing the same thing.

`references` runs the full set once per core and content with its frames
saved as PNG, and lists the screens that stay on for several samples: the
candidates a reviewer looks at before writing them into oracle.yml.

State is .cache/campaign/state.json of the main checkout: per check done,
failed or pending with the reason, and the core sha256, profile digest,
oracle sha256 and record version it ran against. A pass skips what is done
unless one of them changed. The campaign holds the host-wide automation
lock, waits for an idle host, stops cleanly on a busy host or a full disk,
and the next pass a maintainer starts resumes there.

Usage:
    python scripts/campaign.py run [--only CORE,...] [--system ID] [--budget 6h] [--bench]
    python scripts/campaign.py run --dry-run
    python scripts/campaign.py run --commit [--commit-every N]
    python scripts/campaign.py references --only CORE,... [--system ID]
    python scripts/campaign.py status [--json]
    python scripts/campaign.py findings [--all] [--json]
    python scripts/campaign.py review KEY --status applied|rejected --reason TEXT [--set FIELD=YAML]
    python scripts/campaign.py gate

A maintainer starts each pass for a question that names its profiles: no
job runs it on a schedule.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import autorun
import campaign_profiles
import campaign_rules as rules
import core_probe
import measurement_records as mr

ROOT = Path(__file__).resolve().parent.parent
CONTENT_FILE = ROOT / "tests" / "campaign" / "content.yml"
BUILDBOT = "https://buildbot.libretro.com/nightly/linux/x86_64/latest/"
LOCK_HELD_ENV = autorun.LOCK_HELD_ENV
ROMFETCH_ENV = "RETROBIOS_ROMFETCH"
STATE_VERSION = 1

DONE = "done"
FAILED = "failed"
PENDING = "pending"

CRASH_ATTEMPTS = 3
NETWORK_DELAYS = (10, 60, 300)
MAX_ALIAS_CANDIDATES = 6
MAX_REGION_DUMPS = 2
BENCH_WARMUP = 600
BENCH_FRAMES = 1800
BENCH_REPEAT = 5
CHECK_REPEAT = 2
PROBE_TIMEOUT = 900
BUILD_TIMEOUT = 3600
LOG_DAYS = 30
ROMFETCH_TRANSIENT = 3
EXIT_REFUSED = 3


class Pause(RuntimeError):
    """The host cannot run measurements now: the pass stops and resumes later."""


class Unavailable(RuntimeError):
    """A core or a piece of content the campaign cannot get."""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def parse_budget(text: str) -> float:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smh]?)\s*", text or "")
    if not match:
        raise argparse.ArgumentTypeError(f"--budget {text!r}: a number with s, m or h")
    return float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def profile_digest(profile: dict) -> str:
    """What a check depends on in a profile: its entries, evidence left out,
    so the campaign's own evidence never makes it run again."""
    entries = [{k: v for k, v in entry.items() if k != "evidence"}
               for entry in profile.get("files") or []]
    body = {"files": entries, "cores": profile.get("cores"), "type": profile.get("type"),
            "systems": profile.get("systems")}
    return hashlib.sha1(mr.canonical(body)).hexdigest()


def entry_systems(entry: dict, profile: dict) -> list[str]:
    if entry.get("systems"):
        return list(entry["systems"])
    if entry.get("system"):
        return [entry["system"]]
    return list(profile.get("systems") or [])


def entry_dest(entry: dict) -> str:
    """Where the core reads the entry, relative to its system directory."""
    path = entry.get("path")
    if isinstance(path, str) and path and not path.endswith("/"):
        return path
    return entry["name"]


def region_matches(entry: dict, region: str | None) -> bool:
    regions = entry.get("region")
    if not regions or not region:
        return True
    if isinstance(regions, str):
        regions = [regions]
    return region in regions or "world" in regions


def regions_of(entry: dict) -> list[str]:
    regions = entry.get("region") or []
    return [regions] if isinstance(regions, str) else list(regions)


def is_bios(entry: dict) -> bool:
    return entry.get("category", "bios") == "bios" and entry.get("type") != "directory"


# --------------------------------------------------------------------------
# Host
# --------------------------------------------------------------------------

def run_group(argv: Sequence[str], *, timeout: float | None = None, check: bool = False,
              capture_output: bool = False, **kwargs: object) -> subprocess.CompletedProcess:
    """subprocess.run in a process group of its own, the whole group killed
    on a timeout or an interruption: a hung core never outlives its run."""
    if capture_output:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    with subprocess.Popen(list(argv), start_new_session=True, **kwargs) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise
    result = subprocess.CompletedProcess(list(argv), proc.returncode, out, err)
    if check:
        result.check_returncode()
    return result


@dataclass
class Host:
    """What the campaign reads from the machine and the network, replaced in tests."""

    loadavg: Callable[[], tuple[float, float, float]] = os.getloadavg
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    cpu_count: int = os.cpu_count() or 1
    free_gb: Callable[[Path], float] = autorun.free_gb
    poll: float = 60.0
    run: Callable[..., subprocess.CompletedProcess] = run_group
    urlopen: Callable[..., object] = urllib.request.urlopen

    @property
    def max_load(self) -> float:
        return self.cpu_count / 4


@dataclass
class Settings:
    budget: float = 6 * 3600
    max_load_wait: float = 3600
    min_free_gb: float = 30
    cache_cap_gb: float = 20
    probe_timeout: int = PROBE_TIMEOUT
    check_repeat: int = CHECK_REPEAT
    bench_repeat: int = BENCH_REPEAT
    bench_warmup: int = BENCH_WARMUP
    bench_frames: int = BENCH_FRAMES
    romfetch: str = ""
    network: bool = True
    # Benchmarks only choose between variants: never part of a default pass.
    bench: bool = False
    delays: tuple[float, ...] = NETWORK_DELAYS
    echo: bool = True
    # Third-party code (a nightly core, a project's Makefile) runs only under
    # bubblewrap unless this is set.
    allow_unsandboxed: bool = False


@dataclass
class Paths:
    """Where the campaign writes: records and profiles in the checkout it
    runs from, state, cores, logs and content in the main checkout's .cache."""

    root: Path
    home: Path
    content: Path
    db: Path
    content_file: Path = CONTENT_FILE
    oracle: Path = core_probe.DEFAULT_ORACLE

    @property
    def state(self) -> Path:
        return self.home / "state.json"

    @property
    def logs(self) -> Path:
        return self.home / "logs"

    @property
    def emulators(self) -> Path:
        return self.root / "emulators"

    @classmethod
    def default(cls) -> Paths:
        main = autorun.main_checkout()
        return cls(root=ROOT, home=main / ".cache" / "campaign",
                   content=main / ".cache" / "test-content", db=ROOT / "database.json")


ROMFETCH_PASSED = ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME")


def child_env(romfetch: bool = False) -> dict[str, str]:
    """What a program the campaign starts inherits: autorun's allowlist,
    never a token or a password. romfetch also gets its own settings
    (ROMFETCH_*), its account staying in its config file."""
    names: list[str] = [core_probe.PROBE_LOCK_ENV, core_probe.PROBE_LOCK_HELD_ENV]
    if romfetch:
        names += [k for k in os.environ if k.startswith("ROMFETCH_")] + list(ROMFETCH_PASSED)
    return autorun.safe_env(names)


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
        links = {}
        for entry in git_out("-C", str(bare), "ls-tree", "-r", "-z", sha).split(b"\0"):
            if entry.startswith(b"160000 commit "):
                meta, path = entry.split(b"\t", 1)
                links[path.decode()] = meta.split()[2].decode()
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


# The working directory belongs to the process. Two passes in threads that
# each saved and restored it could leave the process in the other's root,
# then in a folder deleted with its workspace.
_CWD_LOCK = threading.Lock()


@contextlib.contextmanager
def working_directory(path: Path) -> Iterator[None]:
    """contextlib.chdir, which Python 3.9 lacks, one thread at a time."""
    with _CWD_LOCK:
        before = Path.cwd()
        os.chdir(path)
        try:
            yield
        finally:
            os.chdir(before)


@contextlib.contextmanager
def host_lock(lock_path: Path) -> Iterator[None]:
    """The automation lock, unless the autorun job running us holds it."""
    if os.environ.get(LOCK_HELD_ENV):
        yield
        return
    with autorun.global_lock(lock_path):
        yield


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        state = {}
    state.setdefault("version", STATE_VERSION)
    for key in ("checks", "cores", "content", "builds", "emulators"):
        state.setdefault(key, {})
    return state


def save_state(path: Path, state: dict) -> None:
    autorun.save_state(path, state)


def should_run(previous: dict | None, core_sha: str, digest: str, oracle_sha: str = "") -> bool:
    """A check runs again when it never ran, is pending, or ran against
    another core build, another version of the profile, another oracle, or
    before records carried a verdict."""
    if not previous:
        return True
    if previous.get("status") == PENDING:
        return True
    return (previous.get("core_sha256") != core_sha or previous.get("profile_digest") != digest
            or previous.get("record_version") != mr.RECORD_VERSION
            or previous.get("oracle_sha256", "") != oracle_sha)


# --------------------------------------------------------------------------
# Content: what each system is tested with, and where it comes from
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Content:
    system: str
    romfetch_system: str
    name: str
    catalog: str
    reason: str
    region: str | None
    load: str
    frames: int
    frame_hash_every: int
    pinned: bool
    boot_file: str | None

    @property
    def key(self) -> str:
        return f"{self.romfetch_system}/{self.name}"


def load_content(path: Path) -> dict[str, list[Content]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, list[Content]] = {}
    for system, spec in (data.get("systems") or {}).items():
        for item in spec.get("content") or ():
            out.setdefault(system, []).append(Content(
                system=system, romfetch_system=str(spec["romfetch"]), name=str(item["name"]),
                catalog=str(item["catalog"]), reason=str(item["reason"]).strip(),
                region=item.get("region"), load=str(item.get("load") or ""),
                frames=int(item.get("frames", 3600)),
                frame_hash_every=int(item.get("frame_hash_every", 10)),
                pinned=bool(item.get("pinned", False)), boot_file=spec.get("boot_file"),
            ))
    return out


def load_file(folder: Path, load: str) -> Path:
    """The file handed to the core."""
    if load == "cue":
        cues = sorted(folder.glob("*.cue"))
        if len(cues) != 1:
            raise Unavailable(f"{folder.name}: {len(cues)} .cue files, one expected")
        return cues[0]
    if load:
        return folder / load
    files = [p for p in sorted(folder.iterdir()) if p.is_file() and p.name != "identity.json"]
    if len(files) != 1:
        raise Unavailable(f"{folder.name}: {len(files)} files, name one with load:")
    return files[0]


def verify_identity(folder: Path) -> dict:
    """The identity.json romfetch wrote, each listed file hashed again."""
    try:
        identity = json.loads((folder / "identity.json").read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise Unavailable(f"{folder}: no identity.json") from exc
    if identity.get("status") != "verified":
        raise Unavailable(f"{folder.name}: identity status {identity.get('status')!r}")
    for item in identity.get("files") or ():
        path = folder / item["name"]
        if not path.is_file() or path.stat().st_size != item["size"] or file_sha1(path) != item["sha1"]:
            raise Unavailable(f"{folder.name}: {item['name']} does not match its identity")
    return identity


def folder_size(folder: Path) -> int:
    return sum(p.stat().st_size for p in folder.rglob("*") if p.is_file())


class ContentStore:
    """Content on disk, its users counted, the least recently used evicted
    past the cap. Only what the campaign fetched is ever deleted, and never
    a pinned entry."""

    def __init__(self, campaign: Campaign) -> None:
        self.c = campaign
        self.state: dict = campaign.state["content"]
        self.refs: dict[str, set[str]] = {}
        self.verified: set[str] = set()

    def folder(self, content: Content) -> Path:
        return self.c.paths.content / content.romfetch_system / content.name

    def hold(self, content: Content, user: str) -> None:
        self.refs.setdefault(content.key, set()).add(user)

    def get(self, content: Content) -> Path:
        """The folder of the content, fetched when absent. Unavailable when not."""
        folder = self.folder(content)
        entry = self.state.setdefault(content.key, {"fetched_by_campaign": False})
        entry["pinned"] = content.pinned
        if not (folder / "identity.json").is_file():
            self.evict(keep={content.key})
            self.fetch(content)
            entry["fetched_by_campaign"] = True
        if content.key not in self.verified:
            identity = verify_identity(folder)
            entry["identity"] = {"catalog": identity.get("catalog"), "dat": identity.get("dat"),
                                 "entry": identity.get("entry")}
            self.verified.add(content.key)
        entry["size"] = folder_size(folder)
        entry["last_used"] = now_iso()
        return folder

    def romfetch(self) -> str | None:
        configured = self.c.settings.romfetch or os.environ.get(ROMFETCH_ENV, "")
        if configured:
            return configured if Path(configured).is_file() or shutil.which(configured) else None
        return shutil.which("romfetch")

    def fetch(self, content: Content) -> None:
        command = self.romfetch()
        if not command:
            raise Unavailable(f"content: romfetch not found, {content.catalog} entry {content.name!r}")
        if not self.c.settings.network:
            raise Unavailable(f"content: offline, {content.catalog} entry {content.name!r}")
        argv = [command, "get", content.romfetch_system, content.name, "--json", "-q",
                "--content-dir", str(self.c.paths.content)]
        for attempt, delay in enumerate((*self.c.settings.delays, None)):
            proc = self.c.host.run(argv, capture_output=True, text=True, check=False,
                                   timeout=6 * 3600, env=child_env(romfetch=True))
            if proc.returncode == 0:
                self.c.log(f"romfetch {content.name}: {proc.stdout.strip()[:300]}")
                return
            code = "unknown"
            with contextlib.suppress(ValueError, AttributeError):
                code = json.loads(proc.stdout)["error"]["code"]
            if proc.returncode != ROMFETCH_TRANSIENT or delay is None:
                raise Unavailable(f"content: romfetch exit {proc.returncode} ({code}) "
                                  f"for {content.name!r}")
            self.c.log(f"romfetch {content.name}: exit {proc.returncode} ({code}), "
                       f"retry {attempt + 1} in {delay}s")
            self.c.host.sleep(delay)

    def release(self, content: Content, user: str) -> None:
        users = self.refs.get(content.key, set())
        users.discard(user)
        if not users:
            self.drop(content.key)

    def deletable(self, key: str) -> bool:
        entry = self.state.get(key) or {}
        return bool(entry.get("fetched_by_campaign")) and not entry.get("pinned")

    def drop(self, key: str) -> bool:
        if not self.deletable(key) or self.refs.get(key):
            return False
        folder = self.c.paths.content / key
        if folder.is_dir():
            shutil.rmtree(folder)
            self.c.log(f"content {key}: deleted, no check left needs it")
        self.state.pop(key, None)
        self.verified.discard(key)
        return True

    def evict(self, keep: set[str]) -> list[str]:
        """Least recently used first, until the campaign's content fits the cap."""
        cap = self.c.settings.cache_cap_gb * 1024 ** 3
        held = sorted((entry.get("last_used", ""), key) for key, entry in self.state.items()
                      if self.deletable(key) and key not in keep)
        total = sum(entry.get("size", 0) for key, entry in self.state.items() if self.deletable(key))
        evicted = []
        for _, key in held:
            if total <= cap:
                break
            size = self.state[key].get("size", 0)
            folder = self.c.paths.content / key
            if folder.is_dir():
                shutil.rmtree(folder)
            self.state.pop(key, None)
            self.verified.discard(key)
            total -= size
            evicted.append(key)
            self.c.log(f"content {key}: evicted, the cache is over {self.c.settings.cache_cap_gb} GB")
        return evicted


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


class Cores:
    """Buildbot nightlies, downloaded once per build, else local builds of
    the profile's pinned commit."""

    def __init__(self, campaign: Campaign) -> None:
        self.c = campaign
        self.listing: set[str] | None = None

    def retrying(self, what: str, call: Callable[[], object]) -> object:
        for attempt, delay in enumerate((*self.c.settings.delays, None)):
            try:
                return call()
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                if isinstance(exc, urllib.error.HTTPError) and exc.code < 500 and exc.code != 429:
                    raise Unavailable(f"{what}: HTTP {exc.code}") from exc
                if delay is None:
                    raise Unavailable(f"{what}: {exc}") from exc
                self.c.log(f"{what}: {exc}, retry {attempt + 1} in {delay}s")
                self.c.host.sleep(delay)
        raise AssertionError("unreachable")

    def buildbot(self) -> set[str]:
        if self.listing is None:
            if not self.c.settings.network:
                self.listing = set()
            else:
                def read() -> bytes:
                    with self.c.host.urlopen(BUILDBOT, timeout=120) as response:
                        return response.read()
                page = self.retrying("buildbot listing", read).decode("utf-8", "replace")
                self.listing = set(re.findall(r"([A-Za-z0-9_]+)_libretro\.so\.zip", page))
        return self.listing

    def names(self, profile: dict) -> list[str]:
        listing = self.buildbot()
        return sorted({str(c) for c in profile.get("cores") or () if str(c) in listing})

    def nightly(self, name: str, profile: dict) -> Core:
        url = f"{BUILDBOT}{name}_libretro.so.zip"
        cached = self.c.state["cores"].get(name) or {}

        def head() -> dict:
            request = urllib.request.Request(url, method="HEAD")
            with self.c.host.urlopen(request, timeout=120) as response:
                return {"etag": response.headers.get("ETag"),
                        "last_modified": response.headers.get("Last-Modified")}
        stamp = self.retrying(f"{name} nightly", head)
        target = self.c.paths.home / "cores" / name / f"{name}_libretro.so"
        if (cached.get("etag"), cached.get("last_modified")) != (stamp["etag"], stamp["last_modified"]) \
                or not target.is_file() or file_sha256(target) != cached.get("sha256"):
            archive = target.parent / f"{name}_libretro.so.zip"
            archive.parent.mkdir(parents=True, exist_ok=True)

            def download() -> None:
                with self.c.host.urlopen(url, timeout=600) as response, archive.open("wb") as out:
                    shutil.copyfileobj(response, out)
            self.retrying(f"{name} nightly", download)
            safe_extract_so(archive, f"{name}_libretro.so", target)
            archive.unlink()
            cached = {**stamp, "url": url, "sha256": file_sha256(target), "fetched_at": now_iso()}
            self.c.state["cores"][name] = cached
            self.c.log(f"core {name}: new nightly {cached['sha256'][:12]} ({stamp['last_modified']})")
        repo = profile.get("source") if isinstance(profile.get("source"), str) else None
        return Core(name, target, cached["sha256"], artifact=url,
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
        return Core(built[0].name.removesuffix("_libretro.so"), built[0], file_sha256(built[0]),
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


# --------------------------------------------------------------------------
# Probe runs
# --------------------------------------------------------------------------

@dataclass
class ProbeResult:
    status: str
    record: dict | None = None
    reason: str = ""
    log: str = ""


@dataclass
class Unit:
    """One core of one emulator profile, with its systems' content."""

    emulator: str
    profile: dict
    core_name: str | None = None
    pending: str = ""
    # A game engine or utility profile: run when the buildbot has its core,
    # otherwise it is a standalone program.
    buildbot_only: bool = False


@dataclass
class Pass:
    started: str
    records: list[str] = field(default_factory=list)
    findings: dict[str, int] = field(default_factory=dict)
    touched: set[str] = field(default_factory=set)
    result: str = "complete"
    detail: str = ""


class Campaign:
    def __init__(self, paths: Paths, settings: Settings | None = None, host: Host | None = None,
                 probe_script: Path | None = None, lock_path: Path | None = None) -> None:
        self.paths = paths
        self.settings = settings or Settings()
        self.host = host or Host()
        self.probe_script = probe_script or ROOT / "scripts" / "core_probe.py"
        self.lock_path = lock_path or Path(os.environ.get(autorun.LOCK_ENV) or autorun.DEFAULT_LOCK)
        self.state = load_state(paths.state)
        self.cores = Cores(self)
        self.store = ContentStore(self)
        self.content = load_content(paths.content_file)
        self.oracle_sha = file_sha256(paths.oracle) if paths.oracle.is_file() else ""
        self.oracle_data = core_probe.load_oracle(paths.oracle)[0]
        self.deadline = 0.0
        self.current: Pass | None = None
        self.dirty_at_start: set[str] = set()
        self._db: dict | None = None

    # -- logging ------------------------------------------------------------

    def log(self, text: str) -> None:
        line = f"{now_iso()} {text}"
        path = self.paths.logs / f"{dt.date.today().isoformat()}.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if self.settings.echo:
            print(line, file=sys.stderr)

    # -- profiles and files -------------------------------------------------

    def profiles(self) -> dict[str, dict]:
        out = {}
        for path in sorted(self.paths.emulators.glob("*.yml")):
            if path.name.startswith("_") or path.stem == "00_example":
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if "emulator" in data:
                out[path.stem] = data
        return out

    @property
    def db(self) -> dict:
        if self._db is None:
            self._db = json.loads(self.paths.db.read_text(encoding="utf-8"))
        return self._db

    def local_file(self, entry: dict) -> Path | None:
        """The collection's copy of an entry, by its declared hashes or its name."""
        from common import resolve_local_file

        hint = entry.get("path") if isinstance(entry.get("path"), str) else ""
        # The database names files relative to the checkout it describes.
        with working_directory(self.paths.root):
            path, status = resolve_local_file(entry, self.db, dest_hint=hint or "")
        if not path or status in ("not_found", "hash_mismatch"):
            return None
        local = Path(path)
        local = local if local.is_absolute() else self.paths.root / local
        return local if local.is_file() else None

    def variant_files(self, entry: dict, primary: Path) -> list[Path]:
        """The .variants/ copies of an entry's file the collection holds."""
        names = [entry["name"], *(entry.get("aliases") or ())]
        out = []
        index = self.db.get("indexes", {}).get("by_name", {})
        for name in names:
            for sha1 in index.get(name, ()):
                path = (self.db["files"].get(sha1) or {}).get("path", "")
                if "/.variants/" in path:
                    local = self.paths.root / path
                    if local.is_file() and local.resolve() != primary.resolve() and local not in out:
                        out.append(local)
        return out

    # -- guards ---------------------------------------------------------------

    def guard(self) -> None:
        """Raise Pause when the pass must stop: budget spent, disk full, host busy."""
        if self.host.clock() >= self.deadline:
            raise Pause("budget")
        free = self.host.free_gb(self.paths.home if self.paths.home.exists() else self.paths.root)
        if free < self.settings.min_free_gb:
            raise Pause(f"disk: {free:.0f} GB free, the campaign stops under "
                        f"{self.settings.min_free_gb:.0f} GB")
        waited = 0.0
        while self.host.loadavg()[0] > self.host.max_load:
            if waited >= self.settings.max_load_wait:
                raise Pause(f"busy host: load stayed above {self.host.max_load:.1f} for "
                            f"{int(waited)} s")
            self.host.sleep(self.host.poll)
            waited += self.host.poll

    # -- one core_probe invocation -------------------------------------------

    def probe(self, argv: list[str], log_name: str) -> ProbeResult:
        """core_probe with retries for a crashing core. Never raises for the core's sake."""
        command = [sys.executable, str(self.probe_script), *argv]
        log = self.paths.logs / dt.date.today().isoformat() / f"{log_name}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        repeats = argv.count("--vary") or 1
        reps = int(argv[argv.index("--repeat") + 1]) if "--repeat" in argv else 1
        budget = self.settings.probe_timeout * repeats * reps + 120
        attempt = busy = 0
        while attempt < CRASH_ATTEMPTS:
            self.guard()
            try:
                proc = self.host.run(command, capture_output=True, text=True, check=False,
                                     timeout=budget, cwd=self.paths.root, env=child_env())
            except subprocess.TimeoutExpired:
                with log.open("a", encoding="utf-8") as handle:
                    handle.write(f"$ {' '.join(command)}\nkilled after {budget} s\n")
                return ProbeResult(FAILED, reason="timeout", log=str(log))
            with log.open("a", encoding="utf-8") as handle:
                handle.write(f"$ {' '.join(command)}\n# exit {proc.returncode}\n"
                             f"{proc.stderr[-20000:]}\n")
            if proc.returncode == 0:
                try:
                    return ProbeResult(DONE, record=json.loads(proc.stdout), log=str(log))
                except ValueError:
                    return ProbeResult(FAILED, reason="core_probe printed no record", log=str(log))
            if proc.returncode == 3:
                # Refused on a busy host: wait for it to settle and run it again.
                busy += 1
                if busy >= CRASH_ATTEMPTS:
                    raise Pause("busy host: core_probe refused to record three times")
                continue
            attempt += 1
            if proc.returncode == 2:
                return ProbeResult(FAILED, reason=f"core_probe refused the run: "
                                                  f"{proc.stderr.strip()[-300:]}", log=str(log))
            if "TimeoutExpired" in proc.stderr or "timed out after" in proc.stderr:
                return ProbeResult(FAILED, reason="timeout", log=str(log))
            self.log(f"{log_name}: attempt {attempt} exited {proc.returncode}")
        return ProbeResult(FAILED, reason=f"crashed {CRASH_ATTEMPTS} times", log=str(log))

    def probe_args(self, mode: str, core: Core, emulator: str, subject: str, content: Content | None,
                   load: Path | None) -> list[str]:
        argv = [mode, "--core", str(core.path), "--record", str(self.paths.root),
                "--emulator", emulator, "--subject", subject,
                "--max-load", str(self.host.max_load), "--timeout", str(self.settings.probe_timeout),
                "--work-dir", str(self.paths.root / "tmp" / "core_probe")]
        if self.paths.oracle.is_file():
            argv += ["--oracle", str(self.paths.oracle)]
        if not self.settings.allow_unsandboxed:
            argv.append("--require-sandbox")
        if core.artifact:
            argv += ["--core-artifact", core.artifact]
        if core.repo:
            argv += ["--core-repo", core.repo]
        if core.commit:
            argv += ["--core-commit", core.commit]
        if core.build_command:
            argv += ["--build-command", core.build_command]
        if content and load:
            argv += ["--content", str(load), "--content-label", content.name]
        return argv

    # -- the checks -------------------------------------------------------------

    def check_key(self, core: Core, content: Content, check: str) -> str:
        return f"{core.name}/{content.system}/{slug(content.name)}/{check}"

    def remember(self, emulator: str, key: str, result: ProbeResult, core: Core | None,
                 digest: str) -> None:
        judged = None
        if result.record and result.record["inputs"].get("content"):
            judged = [result.record["inputs"]["content"]["sha1"], result.record["core"]["library_name"]]
        entry = {"status": result.status, "at": now_iso(), "profile_digest": digest,
                 "core_sha256": core.sha256 if core else None,
                 "record_version": mr.RECORD_VERSION, "oracle_sha256": self.oracle_digest(judged)}
        if judged:
            entry["oracle_key"] = judged
        if result.reason:
            entry["reason"] = result.reason
        if result.log:
            entry["log"] = result.log
        if result.record:
            entry["record"] = result.record["id"]
            if self.current:
                self.current.records.append(result.record["id"])
                self.current.touched.add(mr.records_path(emulator))
        self.state["checks"].setdefault(emulator, {})[key] = entry

    def pending(self, emulator: str, key: str, reason: str, digest: str = "") -> None:
        self.state["checks"].setdefault(emulator, {})[key] = {
            "status": PENDING, "reason": reason, "at": now_iso(), "profile_digest": digest}

    def oracle_digest(self, key: list[str] | None) -> str:
        """What a check's verdicts depend on in the oracle: the entries of its
        content and core, else the whole file. Another core's references
        never make a check run again."""
        if not key:
            return self.oracle_sha
        return mr.value_sha1(core_probe.oracle_for(self.oracle_data, *key))

    def needed(self, emulator: str, key: str, core: Core, digest: str) -> bool:
        previous = self.state["checks"].get(emulator, {}).get(key)
        judged = (previous or {}).get("oracle_key")
        if previous and not judged and previous.get("record"):
            record = self.read_record(emulator, previous["record"]) or {}
            if (record.get("inputs") or {}).get("content"):
                judged = [record["inputs"]["content"]["sha1"], record["core"]["library_name"]]
                previous["oracle_key"] = judged
                # Judged against the entries the record kept, not the file it named.
                kept = {k: v for k, v in (record["inputs"].get("oracle") or {}).items()
                        if k not in ("file", "sha256")}
                previous["oracle_sha256"] = mr.value_sha1({"bios_patterns": [], **kept})
        return should_run(previous, core.sha256, digest, self.oracle_digest(judged))

    def check(self, emulator: str, key: str, core: Core, digest: str, argv: list[str],
              log_name: str) -> dict | None:
        """The record of a check: run now when needed, else the one kept."""
        if not self.needed(emulator, key, core, digest):
            previous = self.state["checks"].get(emulator, {}).get(key) or {}
            return self.read_record(emulator, previous.get("record"))
        result = self.probe(argv, log_name)
        self.remember(emulator, key, result, core, digest)
        return result.record

    def system_entries(self, profile: dict, system: str) -> list[tuple[int, dict]]:
        from validation import filter_files_by_mode

        libretro = filter_files_by_mode(profile.get("files") or [], standalone=False)
        keep = {id(e) for e in libretro}
        return [(i, e) for i, e in enumerate(profile.get("files") or [])
                if id(e) in keep and system in entry_systems(e, profile) and is_bios(e)]

    def boot_entry(self, entries: list[tuple[int, dict]], content: Content) -> tuple[int, dict] | None:
        held = [(i, e) for i, e in entries if region_matches(e, content.region) and self.local_file(e)]
        if content.boot_file:
            named = [(i, e) for i, e in held
                     if content.boot_file in (e["name"], *(e.get("aliases") or ()))]
            if named:
                return named[0]
        held.sort(key=lambda item: (item[1].get("priority", 1 << 30), item[0]))
        return held[0] if held else None

    @staticmethod
    def other_regions(entry: dict, staged: dict[str, tuple[int, dict, Path]], local: Path) -> list[Path]:
        """Held dumps of the same system for regions this entry does not
        serve, one per distinct file: the wrong-region variants."""
        mine = set(regions_of(entry))
        if not mine or "world" in mine:
            return []
        out: dict[str, Path] = {}
        for _, other, path in staged.values():
            theirs = set(regions_of(other))
            if theirs and "world" not in theirs and not theirs & mine and path.resolve() != local.resolve():
                out.setdefault(file_sha1(path), path)
        return sorted(out.values(), key=lambda p: p.name)[:MAX_REGION_DUMPS]

    def run_unit_content(self, unit: Unit, core: Core, content: Content, digest: str) -> None:
        emulator, profile = unit.emulator, unit.profile
        entries = self.system_entries(profile, content.system)
        staged: dict[str, tuple[int, dict, Path]] = {}
        for index, entry in entries:
            local = self.local_file(entry)
            if local and entry_dest(entry) not in staged:
                staged[entry_dest(entry)] = (index, entry, local)
        tested = {dest: item for dest, item in staged.items() if region_matches(item[1], content.region)}
        keys = {"files": self.check_key(core, content, "files"),
                "none": self.check_key(core, content, "none")}
        for dest in tested:
            keys[f"negative:{dest}"] = self.check_key(core, content, f"negative:{dest}")
        if self.settings.bench:
            keys["bench"] = self.check_key(core, content, "bench")
        # The rules run on every pass, from the records kept when nothing
        # needs to run again: a change of the table applies without a run.
        try:
            folder = self.store.get(content)
            load = load_file(folder, content.load)
        except Unavailable as exc:
            for key in keys.values():
                if self.needed(emulator, key, core, digest):
                    self.pending(emulator, key, str(exc), digest)
            return
        frames = ["--frames", str(content.frames), "--frame-hash-every", str(content.frame_hash_every)]
        repeat = ["--repeat", str(self.settings.check_repeat)]
        stem = f"{core.name}-{slug(content.name)}"

        # files: every declared file the collection holds, at its place.
        argv = self.probe_args("run", core, emulator, slug(f"files-{stem}"), content, load) + frames + repeat
        for dest, (_, _, local) in sorted(staged.items()):
            argv += ["--system-file", f"{dest}={local}"]
        files_record = self.check(emulator, keys["files"], core, digest, argv, f"{emulator}-{stem}-files")
        # none: no BIOS at all.
        argv = self.probe_args("run", core, emulator, slug(f"none-{stem}"), content, load) + frames + repeat
        none_record = self.check(emulator, keys["none"], core, digest, argv, f"{emulator}-{stem}-none")
        if not files_record or not none_record:
            return
        full = rules.run_of(files_record, files_record["variants"][0]["label"])
        none = rules.run_of(none_record, none_record["variants"][0]["label"])
        self.log(f"{emulator}: {core.name} on {content.name}: full set {full.verdict}, "
                 f"no BIOS {none.verdict}")

        for dest, (index, entry, local) in sorted(tested.items()):
            record = self.negative(unit, core, content, load, frames, digest, keys[f"negative:{dest}"],
                                   dest, entry, local, staged)
            if not record:
                continue
            labels = [v["label"] for v in record["variants"]]
            present = rules.run_of(record, labels[0])
            zeros, half = (rules.run_of(record, label) for label in labels[1:3])
            for label in labels[3:]:
                self.log(f"{emulator}: {rules.rule_region(rules.run_of(record, label), present, entry, content.region)}")
            if dest in self.opened(files_record, 0) or dest in self.opened(record, 0):
                verdicts = rules.rule_need(none, present, entry, rules.read(none, present, zeros, half))
                validation = rules.rule_validation(zeros, half, none, present, entry)
                if validation:
                    verdicts.append(validation)
                self.settle(emulator, content, core, index, entry, verdicts)
                variants = self.variant_files(entry, local)
                if variants:
                    self.run_variants(unit, core, content, load, frames, digest, index, entry, dest,
                                      local, variants)
            else:
                self.moved(unit, core, content, load, frames, digest, index, entry, dest, local,
                           files_record, record)

        boot = self.boot_entry(entries, content)
        if boot and entry_dest(boot[1]) in tested:
            index, entry = boot
            self.follow_aliases(unit, core, content, load, frames, digest, index, entry,
                                tested[entry_dest(entry)][2], none_record)

        if self.settings.bench and full.verdict == rules.BOOTS:
            argv = self.probe_args("bench", core, emulator, slug(f"bench-{stem}"), content, load)
            argv += ["--warmup", str(self.settings.bench_warmup), "--frames",
                     str(self.settings.bench_frames), "--repeat", str(self.settings.bench_repeat),
                     "--no-trace"]
            if boot:
                argv += ["--system-file", f"{entry_dest(boot[1])}={self.local_file(boot[1])}"]
            self.check(emulator, keys["bench"], core, digest, argv, f"{emulator}-{stem}-bench")

    def negative(self, unit: Unit, core: Core, content: Content, load: Path, frames: list[str],
                 digest: str, key: str, dest: str, entry: dict, local: Path,
                 staged: dict[str, tuple[int, dict, Path]]) -> dict | None:
        """The file alone, then wrong files under its name: zeros of its
        size, its first half, and other regions' dumps."""
        stem = f"{core.name}-{slug(content.name)}"
        size = local.stat().st_size
        others = self.other_regions(entry, staged, local)
        argv = self.probe_args("check", core, unit.emulator, slug(f"negative-{entry['name']}-{stem}"),
                               content, load) + frames
        argv += ["--vary", f"{dest}={local}", "--vary", f"{dest}=@zeros:{size}",
                 "--vary", f"{dest}=@head:{size // 2}:{local}"]
        for other in others:
            argv += ["--vary", f"{dest}={other}"]
        regions = f", then {', '.join(p.name for p in others)} staged under its name" if others else ""
        argv += ["--observable", "frame_hashes", "--repeat", str(self.settings.check_repeat),
                 "--claim", (f"{core.name} boots {content.name} with {entry['name']} alone and "
                             f"refuses a wrong file under its name"),
                 "--method", (f"{entry['name']} alone as {dest}, then {size} zero bytes and its "
                              f"first {size // 2} bytes{regions}, nothing else staged. Each run "
                              f"{self.settings.check_repeat} times from a fresh process for "
                              f"{content.frames} frames with no button pressed, every "
                              f"{content.frame_hash_every}th frame hashed. The boot oracle judges "
                              f"each variant against the reference frames of {content.name}.")]
        return self.check(unit.emulator, key, core, digest, argv, f"{unit.emulator}-{stem}-negative")

    def moved(self, unit: Unit, core: Core, content: Content, load: Path, frames: list[str],
              digest: str, index: int, entry: dict, dest: str, local: Path, files_record: dict,
              alone: dict) -> None:
        """A file the core opened neither in the full set nor alone: where
        else it looked for a file of that name, else flagged."""
        probed = [p for record in (files_record, alone) for r in record["variants"][0]["repetitions"]
                  for p in r.get("files_probed_absent") or ()]
        others = [p for p in dict.fromkeys(probed) if p != dest
                  and p.rsplit("/", 1)[-1].casefold() == dest.rsplit("/", 1)[-1].casefold()]
        for candidate in others[:MAX_ALIAS_CANDIDATES]:
            found = self.follow_up(unit, core, content, load, frames, digest, entry, local, candidate,
                                   f"path:{entry['name']}:{candidate}")
            if found and candidate in self.opened(found, 0):
                verdict = rules.rule_path(entry, dest, rules.Opened(candidate, found["id"]))
                if verdict:
                    self.settle(unit.emulator, content, core, index, entry, [verdict])
                    return
        verdict = rules.rule_never_opened(entry, [files_record["id"], alone["id"]], content.name)
        self.settle(unit.emulator, content, core, index, entry, [verdict])

    def read_record(self, emulator: str, rid: str | None) -> dict | None:
        """A record by its id, or the record that supersedes it: a run
        judged again offline is read as judged last."""
        if not rid:
            return None
        path = self.paths.root / mr.records_path(emulator)
        if not path.is_file():
            return None
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        by_id = {r["id"]: r for r in records}
        successor = {r["supersedes"]: r["id"] for r in records if r.get("supersedes")}
        seen = set()
        while rid in successor and rid not in seen:
            seen.add(rid)
            rid = successor[rid]
        return by_id.get(rid)

    def judged(self, emulator: str, rid: str) -> bool:
        """True for a record the boot oracle judged: only those prove a field."""
        record = self.read_record(emulator, rid)
        return bool(record) and record.get("record_version", 0) >= 4

    @staticmethod
    def opened(record: dict, position: int) -> set[str]:
        out: set[str] = set()
        for rep in record["variants"][position]["repetitions"]:
            out |= {item["path"] for item in rep.get("files_opened") or ()}
        return out

    def follow_up(self, unit: Unit, core: Core, content: Content, load: Path, frames: list[str],
                  digest: str, entry: dict, local: Path, dest: str, check: str) -> dict | None:
        """The file staged at dest alone: does the core open it there."""
        stem = f"{core.name}-{slug(content.name)}"
        argv = self.probe_args("run", core, unit.emulator, slug(f"{check}-{stem}"), content, load)
        argv += frames + ["--system-file", f"{dest}={local}"]
        return self.check(unit.emulator, self.check_key(core, content, check), core, digest, argv,
                          f"{unit.emulator}-{stem}-{slug(check)}")

    def follow_aliases(self, unit: Unit, core: Core, content: Content, load: Path, frames: list[str],
                       digest: str, index: int, entry: dict, local: Path, none_record: dict) -> None:
        """Names the core looked for, with no BIOS, that no entry declares."""
        declared = {e["name"] for e in unit.profile.get("files") or ()}
        declared |= {a for e in unit.profile.get("files") or () for a in e.get("aliases") or ()}
        suffix = Path(entry["name"]).suffix.casefold()
        dest = entry_dest(entry)
        folder = dest.rsplit("/", 1)[0] if "/" in dest else ""
        probed: list[str] = []
        for rep in none_record["variants"][0]["repetitions"]:
            for path in rep.get("files_probed_absent") or ():
                name = path.rsplit("/", 1)[-1]
                where = path.rsplit("/", 1)[0] if "/" in path else ""
                if (where == folder and name not in declared and Path(name).suffix.casefold() == suffix
                        and path not in probed):
                    probed.append(path)
        for candidate in probed[:MAX_ALIAS_CANDIDATES]:
            found = self.follow_up(unit, core, content, load, frames, digest, entry, local, candidate,
                                   f"alias:{entry['name']}:{candidate.rsplit('/', 1)[-1]}")
            if found and candidate in self.opened(found, 0):
                verdict = rules.rule_alias(self.reload_entry(unit, index), rules.Opened(candidate, found["id"]))
                if verdict:
                    self.settle(unit.emulator, content, core, index, self.reload_entry(unit, index), [verdict])

    def run_variants(self, unit: Unit, core: Core, content: Content, load: Path, frames: list[str],
                     digest: str, index: int, entry: dict, dest: str, primary: Path,
                     variants: list[Path]) -> None:
        key = self.check_key(core, content, f"variants:{entry['name']}")
        if not self.needed(unit.emulator, key, core, digest):
            return
        stem = f"{core.name}-{slug(content.name)}"
        argv = self.probe_args("check", core, unit.emulator, slug(f"variants-{entry['name']}-{stem}"),
                               content, load) + frames
        for path in [primary, *variants]:
            argv += ["--vary", f"{dest}={path}"]
        argv += ["--observable", "frame_hashes", "--repeat", str(self.settings.check_repeat),
                 "--claim", f"every copy of {entry['name']} boots {content.name} on {core.name}",
                 "--method", (f"Each copy the collection holds staged alone as {dest}, each run "
                              f"{self.settings.check_repeat} times for {content.frames} frames. The "
                              f"boot oracle judges each copy.")]
        record = self.check(unit.emulator, key, core, digest, argv, f"{unit.emulator}-{stem}-variants")
        if record:
            verdict = rules.rule_variants([rules.run_of(record, v["label"]) for v in record["variants"]],
                                          entry)
            if verdict:
                self.settle(unit.emulator, content, core, index, entry, [verdict])

    # -- verdicts -----------------------------------------------------------------

    def reload_entry(self, unit: Unit, index: int) -> dict:
        path = self.paths.emulators / f"{unit.emulator}.yml"
        unit.profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        return unit.profile["files"][index]

    def settle(self, emulator: str, content: Content, core: Core, index: int, entry: dict,
               verdicts: Sequence[rules.Verdict]) -> None:
        """Apply what the table settles, queue the rest, resolve what now agrees."""
        path = self.paths.emulators / f"{emulator}.yml"
        for verdict in verdicts:
            fresh = (yaml.safe_load(path.read_text(encoding="utf-8")).get("files") or [])[index]
            if fresh.get("name") != entry.get("name"):
                self.log(f"{emulator}: files[{index}] is no longer {entry.get('name')}, nothing applied")
                return
            says = rules.current(fresh, verdict.field) if verdict.field in rules.SETTLED_FIELDS \
                else None
            agrees = verdict.field in rules.SETTLED_FIELDS and rules.agrees(fresh, verdict)
            if verdict.apply:
                updates: dict[str, object] = {}
                if not agrees or (verdict.field not in fresh and verdict.field != "validation"):
                    updates[verdict.field] = verdict.value
                evidence = rules.merge_evidence(fresh.get("evidence"), verdict,
                                                keep=lambda rid: self.judged(emulator, rid))
                if evidence != fresh.get("evidence"):
                    updates["evidence"] = evidence
                if updates:
                    try:
                        changed = campaign_profiles.write_fields(path, index, updates)
                    except campaign_profiles.ProfileEditError as exc:
                        self.finding(emulator, content, core, fresh, verdict, "open", says,
                                     extra=f". Not written: {exc}")
                        continue
                    if changed and self.current:
                        self.current.touched.add(path.relative_to(self.paths.root).as_posix())
                if agrees:
                    self.resolve(emulator, content, core, fresh, verdict, says)
                else:
                    self.finding(emulator, content, core, fresh, verdict, "applied", says)
                continue
            if verdict.rule == "never_opened":
                self.finding(emulator, content, core, fresh, verdict, "flagged", None)
            elif agrees:
                self.resolve(emulator, content, core, fresh, verdict, says)
            else:
                self.finding(emulator, content, core, fresh, verdict, "open", says)

    def finding_key(self, emulator: str, content: Content, entry: dict, verdict: rules.Verdict) -> str:
        return f"{emulator}/{content.system}/{entry['name']}/{verdict.field}"

    def latest_findings(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for line in mr.read_campaign(self.paths.root, mr.FINDINGS):
            latest[line["key"]] = line
        return latest

    def finding(self, emulator: str, content: Content, core: Core, entry: dict,
                verdict: rules.Verdict, status: str, says: object, extra: str = "") -> None:
        key = self.finding_key(emulator, content, entry, verdict)
        previous = self.latest_findings().get(key)
        if previous and previous["status"] == status and previous["rule"] == verdict.rule \
                and previous["run_shows"] == verdict.value and previous["profile_says"] == says \
                and previous["evidence"] == list(verdict.evidence):
            return
        # A review that read the code and kept the profile stands while the
        # runs keep showing the same thing.
        if previous and previous["status"] == "rejected" and status == "open" \
                and previous["rule"] == verdict.rule and previous["run_shows"] == verdict.value \
                and previous["profile_says"] == says:
            return
        line = mr.seal_line({
            "schema_version": 1, "found_at": now_iso(), "key": key, "emulator": emulator,
            "system": content.system, "file": entry["name"], "field": verdict.field,
            "status": status, "rule": verdict.rule, "profile_says": says, "run_shows": verdict.value,
            "statement": verdict.statement + extra, "evidence": list(verdict.evidence),
            "core": {"file": core.path.name, "sha256": core.sha256,
                     "library_version": self.library_version(emulator, verdict.evidence)},
            "content": content.name,
        }, "found_at")
        path = self.paths.root / mr.records_path(mr.FINDINGS)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(mr.line_text(line) + "\n")
        if self.current:
            self.current.findings[status] = self.current.findings.get(status, 0) + 1
            self.current.touched.add(mr.records_path(mr.FINDINGS))
        self.log(f"finding {status}: {key}: {verdict.statement}")

    def resolve(self, emulator: str, content: Content, core: Core, entry: dict,
                verdict: rules.Verdict, says: object) -> None:
        previous = self.latest_findings().get(self.finding_key(emulator, content, entry, verdict))
        if previous and previous["status"] in ("open", "flagged"):
            self.finding(emulator, content, core, entry, verdict, "resolved", says)

    def library_version(self, emulator: str, ids: Sequence[str]) -> str | None:
        for rid in ids:
            record = self.read_record(emulator, rid)
            if record:
                return record["core"].get("library_version")
        return None

    # -- reference frames -----------------------------------------------------------

    def references(self, only: set[str], system: str | None, png_dir: Path) -> list[dict]:
        """The full set run once per core and content, frames written as PNG,
        and the screens that stay on long enough to serve as references."""
        self.deadline = self.host.clock() + self.settings.budget
        listed = []
        for unit in self.units(only, system):
            contents = self.unit_contents(unit, system)
            if unit.pending or not contents:
                continue
            try:
                cores = self.unit_cores(unit.emulator, unit.profile, unit.buildbot_only)
            except Unavailable as exc:
                self.log(f"{unit.emulator}: {exc}")
                continue
            for core in cores:
                for content in contents:
                    self.guard()
                    self.store.hold(content, "references")
                    try:
                        load = load_file(self.store.get(content), content.load)
                    except Unavailable as exc:
                        self.log(f"{unit.emulator}: {exc}")
                        continue
                    stem = f"{core.name}-{slug(content.name)}"
                    target = png_dir / slug(core.name) / slug(content.name)
                    shutil.rmtree(target, ignore_errors=True)
                    argv = self.probe_args("run", core, unit.emulator, slug(f"references-{stem}"),
                                           content, load)
                    argv += ["--frames", str(content.frames), "--frame-hash-every",
                             str(content.frame_hash_every), "--repeat", str(self.settings.check_repeat),
                             "--png-dir", str(target)]
                    for index, entry in self.system_entries(unit.profile, content.system):
                        local = self.local_file(entry)
                        if local and f"{entry_dest(entry)}=" not in " ".join(argv):
                            argv += ["--system-file", f"{entry_dest(entry)}={local}"]
                    result = self.probe(argv, f"{unit.emulator}-{stem}-references")
                    self.store.release(content, "references")
                    if not result.record:
                        self.log(f"{unit.emulator}: references of {content.name}: {result.reason}")
                        continue
                    record = result.record
                    listed.append({
                        "emulator": unit.emulator, "core": core.name,
                        "library_name": record["core"]["library_name"], "content": content.name,
                        "content_sha1": record["inputs"]["content"]["sha1"], "record": record["id"],
                        "verdict": record["variants"][0]["verdict"],
                        "png_dir": str(target / record["variants"][0]["label"]),
                        "candidates": reference_candidates(record),
                    })
        save_state(self.paths.state, self.state)
        return listed

    # -- the pass -----------------------------------------------------------------

    def units(self, only: set[str], system: str | None) -> list[Unit]:
        out = []
        for emulator, profile in sorted(self.profiles().items()):
            cores = {str(c) for c in profile.get("cores") or ()}
            if only and emulator not in only and not (cores & only):
                continue
            systems = set(profile.get("systems") or ())
            if system and system not in systems:
                continue
            kind = str(profile.get("type") or "")
            if kind in ("alias", "launcher", "test"):
                continue
            if "libretro" in kind or kind in ("game", "utility"):
                out.append(Unit(emulator, profile, buildbot_only="libretro" not in kind))
                continue
            out.append(Unit(emulator, profile, pending="standalone"))
        return out

    def unit_contents(self, unit: Unit, system: str | None) -> list[Content]:
        systems = [s for s in unit.profile.get("systems") or () if not system or s == system]
        return [c for s in systems for c in self.content.get(s, ())]

    def run(self, only: set[str], system: str | None, dry_run: bool = False,
            commit_every: int = 0, commit: bool = False) -> Pass:
        self.deadline = self.host.clock() + self.settings.budget
        current = self.current = Pass(started=now_iso())
        units = self.units(only, system)
        if dry_run:
            self.describe(units, system)
            return current
        isolation = core_probe.sandbox_argv([])[1]
        if isolation != core_probe.SANDBOX and not self.settings.allow_unsandboxed:
            # Fail closed: no core and no build runs outside the sandbox.
            current.result = "refused"
            current.detail = (f"no sandbox for third-party code ({isolation}). Install bubblewrap, "
                              f"or pass --allow-unsandboxed")
            self.log(f"pass refused: {current.detail}")
            self.write_run_line(current)
            save_state(self.paths.state, self.state)
            return current
        for unit in units:
            for content in self.unit_contents(unit, system):
                self.store.hold(content, unit.emulator)
        done_units = 0
        try:
            for unit in units:
                self.run_unit(unit, system)
                done_units += 1
                save_state(self.paths.state, self.state)
                if commit and commit_every and done_units % commit_every == 0:
                    self.commit_batch()
        except Pause as exc:
            current.result = "budget" if str(exc) == "budget" else "paused"
            current.detail = str(exc)
            self.log(f"pass paused: {exc}")
        except KeyboardInterrupt:
            current.result, current.detail = "stopped", "interrupted"
        finally:
            for unit in units:
                for content in self.unit_contents(unit, system):
                    self.store.release(content, unit.emulator)
            self.prune_logs()
            self.write_run_line(current)
            save_state(self.paths.state, self.state)
        if commit:
            self.commit_batch()
        return current

    def run_unit(self, unit: Unit, system: str | None) -> None:
        emulator, profile = unit.emulator, unit.profile
        digest = profile_digest(profile)
        contents = self.unit_contents(unit, system)
        systems = [s for s in profile.get("systems") or () if not system or s == system]
        if unit.pending:
            for s in systems:
                self.pending(emulator, f"*/{s}/*", unit.pending, digest)
            return
        if not contents:
            for s in systems:
                self.pending(emulator, f"*/{s}/*", f"content: no test content listed for {s}", digest)
            return
        try:
            cores = self.unit_cores(emulator, profile, unit.buildbot_only)
        except Unavailable as exc:
            for s in systems:
                self.pending(emulator, f"*/{s}/*", str(exc), digest)
            self.log(f"{emulator}: {exc}")
            return
        for s in systems:
            self.state["checks"].setdefault(emulator, {}).pop(f"*/{s}/*", None)
        for core in cores:
            self.log(f"{emulator}: core {core.name} {core.sha256[:12]}")
            for content in contents:
                self.guard()
                self.run_unit_content(Unit(emulator, profile, core.name), core, content, digest)
        for content in contents:
            self.store.release(content, emulator)
        self.state["emulators"][emulator] = {"profile_digest": profile_digest(
            yaml.safe_load((self.paths.emulators / f"{emulator}.yml").read_text(encoding="utf-8"))),
            "at": now_iso()}
        # The campaign's own edits do not make its checks run again.
        new_digest = self.state["emulators"][emulator]["profile_digest"]
        for entry in self.state["checks"].get(emulator, {}).values():
            if entry.get("profile_digest") == digest:
                entry["profile_digest"] = new_digest

    def unit_cores(self, emulator: str, profile: dict, buildbot_only: bool = False) -> list[Core]:
        names = self.cores.names(profile)
        if names:
            return [self.cores.nightly(name, profile) for name in names]
        if buildbot_only:
            raise Unavailable("standalone: no libretro core on the buildbot")
        return [self.cores.build(emulator, profile)]

    def describe(self, units: list[Unit], system: str | None) -> None:
        for unit in units:
            contents = self.unit_contents(unit, system)
            if unit.pending:
                print(f"{unit.emulator}: pending, {unit.pending}")
            elif not contents:
                print(f"{unit.emulator}: pending, no test content for "
                      f"{', '.join(unit.profile.get('systems') or ())}")
            else:
                cores = sorted({str(c) for c in unit.profile.get("cores") or ()})
                print(f"{unit.emulator}: cores {', '.join(cores)} on "
                      f"{', '.join(c.name for c in contents)}")

    def counts(self) -> tuple[dict[str, int], dict[str, int], list[dict]]:
        counts = {DONE: 0, FAILED: 0, PENDING: 0}
        reasons: dict[str, int] = {}
        failed = []
        for emulator, checks in sorted(self.state["checks"].items()):
            for key, entry in sorted(checks.items()):
                status = entry.get("status", PENDING)
                counts[status] = counts.get(status, 0) + 1
                if status == PENDING:
                    reason = reason_class(entry.get("reason", ""))
                    reasons[reason] = reasons.get(reason, 0) + 1
                elif status == FAILED:
                    failed.append({"emulator": emulator, "check": key, "reason": entry.get("reason", "")})
        return counts, reasons, failed

    def write_run_line(self, current: Pass) -> None:
        counts, reasons, failed = self.counts()
        line = mr.seal_line({
            "schema_version": 1, "started_at": current.started, "ended_at": now_iso(),
            "result": current.result, "detail": current.detail, "counts": counts,
            "pending_reasons": reasons, "failed": failed, "records": current.records,
            "findings": dict(sorted(current.findings.items())),
        }, "started_at")
        path = self.paths.root / mr.records_path(mr.CAMPAIGN_RUNS)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(mr.line_text(line) + "\n")
        current.touched.add(mr.records_path(mr.CAMPAIGN_RUNS))
        self.state["last_run"] = {k: line[k] for k in ("id", "started_at", "ended_at", "result", "detail")}

    def prune_logs(self) -> None:
        limit = time.time() - LOG_DAYS * 86400
        for path in self.paths.logs.rglob("*.log") if self.paths.logs.is_dir() else ():
            if path.stat().st_mtime < limit:
                path.unlink()

    # -- commits (direct runs, autorun commits by its own rules) -------------------

    def plan_commits(self, dirty_at_start: set[str]) -> list[tuple[str, list[str]]]:
        """(subject, paths) of each commit: the records, then one per profile."""
        touched = sorted(self.current.touched if self.current else ())
        records = [p for p in touched if p.startswith(f"{mr.RECORDS_DIR}/") and p not in dirty_at_start]
        plan = []
        if records:
            plan.append(("chore: add campaign measurements", records))
        for path in touched:
            if path.startswith("emulators/") and path not in dirty_at_start:
                subject = f"chore: apply tested fields to {Path(path).stem}"
                if len(subject) > 50:
                    subject = "chore: apply tested profile fields"
                plan.append((subject, [path]))
        return plan

    def commit_batch(self, dry_run: bool = False) -> list[str]:
        plan = self.plan_commits(self.dirty_at_start)
        if dry_run or not plan:
            for subject, paths in plan:
                print(f"would commit {subject!r}: {', '.join(paths)}")
            return []
        if gate(self.paths.root, [Path(p).stem for _, ps in plan for p in ps if p.startswith("emulators/")],
                self.host) != 0:
            self.log("gate failed, nothing committed")
            return []
        made = []
        for subject, paths in plan:
            problems = autorun.check_subject(subject)
            if problems:
                raise ValueError(f"{subject!r}: {', '.join(problems)}")
            made.append(autorun.commit_paths(self.paths.root, paths, autorun.CommitRule(subject, tuple(paths))))
        if self.current:
            self.current.touched.clear()
        return made


def reference_candidates(record: dict, min_samples: int = 3) -> list[dict]:
    """Screens of a record's first variant that are not one colour and stay
    on for at least min_samples consecutive samples in every repetition:
    what a reviewer looks at to choose reference frames."""
    found: list[dict[str, tuple[int, int]]] = []
    for rep in record["variants"][0]["repetitions"]:
        observables = rep.get("observables") or {}
        uniform = set(observables.get("uniform_frames") or ())
        runs: dict[str, tuple[int, int]] = {}
        previous, start, length = None, 0, 0
        for frame, digest in [*(observables.get("frame_hashes") or ()), (None, None)]:
            if digest == previous:
                length += 1
                continue
            if previous and previous not in uniform and length >= min_samples:
                first, longest = runs.get(previous, (start, 0))
                runs[previous] = (min(first, start), max(longest, length))
            previous, start, length = digest, frame, 1
        found.append(runs)
    common = set(found[0]) if found else set()
    for runs in found[1:]:
        common &= set(runs)
    return sorted(({"sha1": digest, "first_frame": found[0][digest][0], "samples": found[0][digest][1]}
                   for digest in common), key=lambda item: item["first_frame"])


def reason_class(reason: str) -> str:
    """A pending reason without its detail, to count them."""
    head = reason.split(":", 1)[0].strip() if ":" in reason else reason
    return head or "unknown"


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------

def gate(root: Path, emulators: Sequence[str], host: Host | None = None) -> int:
    """The measurement tests, the schemas, and verify plus an emulator pack
    for each profile the campaign changed."""
    host = host or Host()
    python = sys.executable
    steps = [
        [python, "-m", "unittest", "tests.test_measurements", "tests.test_campaign"],
        [python, "scripts/validate_schemas.py", "--source-only"],
    ]
    for emulator in sorted(set(emulators)):
        steps.append([python, "scripts/verify.py", "--emulator", emulator])
        steps.append([python, "scripts/generate_pack.py", "--emulator", emulator, "--offline",
                      "--output-dir", "tmp/campaign/packs"])
    for argv in steps:
        proc = host.run(argv, cwd=root, check=False)
        if proc.returncode != 0:
            print(f"gate: {' '.join(argv)} exited {proc.returncode}", file=sys.stderr)
            return 1
    shutil.rmtree(root / "tmp" / "campaign" / "packs", ignore_errors=True)
    return 0


def changed_profiles(root: Path) -> list[str]:
    return [Path(p).stem for p in autorun.changed_files(root)
            if p.startswith("emulators/") and p.endswith(".yml")]


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

def status_report(campaign: Campaign) -> dict:
    counts, reasons, failed = campaign.counts()
    runs = mr.read_campaign(campaign.paths.root, mr.CAMPAIGN_RUNS)
    per = {}
    for emulator, checks in sorted(campaign.state["checks"].items()):
        per[emulator] = {key: {k: v for k, v in entry.items() if k in ("status", "reason", "record", "at")}
                         for key, entry in sorted(checks.items())}
    return {"last_run": runs[-1] if runs else None, "counts": counts, "pending_reasons": reasons,
            "failed": failed, "emulators": per}


def render_status(report: dict) -> str:
    lines = []
    last = report["last_run"]
    if last:
        lines.append(f"last run {last['started_at']} to {last['ended_at']}: {last['result']}"
                     + (f" ({last['detail']})" if last["detail"] else ""))
    else:
        lines.append("no run yet")
    counts = report["counts"]
    lines.append(f"{counts.get(DONE, 0)} done, {counts.get(FAILED, 0)} failed, "
                 f"{counts.get(PENDING, 0)} pending")
    for reason, number in sorted(report["pending_reasons"].items(), key=lambda kv: -kv[1]):
        lines.append(f"  pending {number:5}  {reason}")
    for item in report["failed"]:
        lines.append(f"  FAILED {item['emulator']} {item['check']}: {item['reason']}")
    for emulator, checks in report["emulators"].items():
        ran = [k for k, v in checks.items() if v["status"] != PENDING]
        if ran:
            lines.append(f"{emulator}")
            for key in ran:
                entry = checks[key]
                lines.append(f"  {entry['status']:7} {key}" + (f"  {entry['record']}" if entry.get("record") else "")
                             + (f"  ({entry['reason']})" if entry.get("reason") else ""))
    return "\n".join(lines)


def open_findings(root: Path, everything: bool = False) -> list[dict]:
    latest: dict[str, dict] = {}
    for line in mr.read_campaign(root, mr.FINDINGS):
        latest[line["key"]] = line
    return [line for key, line in sorted(latest.items())
            if everything or line["status"] in ("open", "flagged")]


REVIEWED = ("applied", "rejected")


def review_finding(root: Path, key: str, status: str, reason: str,
                   updates: dict[str, object] | None = None, index: int | None = None) -> dict:
    """Close an open finding after reading the core's code.

    `applied` writes `updates` into the entry the finding names, through the
    same editor as the rule table, with the finding's record ids added as
    `evidence:` under its field. An applied finding with no update records a
    profile changed by hand. `rejected` keeps the profile as it is. Either
    way a line with the reason is appended to the findings."""
    if status not in REVIEWED:
        raise ValueError(f"status {status!r}: one of {', '.join(REVIEWED)}")
    if not reason.strip():
        raise ValueError("a review names its reason")
    latest = {line["key"]: line for line in mr.read_campaign(root, mr.FINDINGS)}
    finding = latest.get(key)
    if finding is None:
        raise ValueError(f"no finding {key}")
    if finding["status"] not in ("open", "flagged"):
        raise ValueError(f"{key} is {finding['status']}, not open")
    if updates and status != "applied":
        raise ValueError("only an applied review changes the profile")
    if updates:
        path = root / "emulators" / f"{finding['emulator']}.yml"
        entries = yaml.safe_load(path.read_text(encoding="utf-8")).get("files") or []
        matches = [i for i, entry in enumerate(entries) if entry.get("name") == finding["file"]]
        if index is not None:
            matches = [i for i in matches if i == index]
        if len(matches) != 1:
            raise ValueError(f"{finding['emulator']}: {len(matches)} entries named {finding['file']}"
                             + ("" if index is not None else ", pass --index"))
        entry = entries[matches[0]]
        verdict = rules.Verdict(finding["rule"], finding["field"], finding["run_shows"],
                                finding["statement"], tuple(finding["evidence"]))
        evidence = rules.merge_evidence(entry.get("evidence"), verdict)
        campaign_profiles.write_fields(path, matches[0], {**updates, "evidence": evidence})
    body = {key_: value for key_, value in finding.items() if key_ != "id"}
    line = mr.seal_line({**body, "found_at": now_iso(), "status": status, "reason": reason},
                        "found_at")
    with (root / mr.records_path(mr.FINDINGS)).open("a", encoding="utf-8") as handle:
        handle.write(mr.line_text(line) + "\n")
    return line


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    scope = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    scope.add_argument("--only", default="", help="emulator profiles or core names, comma-separated")
    scope.add_argument("--system", help="one system id")
    scope.add_argument("--romfetch", default="",
                       help=f"romfetch command (default: ${ROMFETCH_ENV}, else romfetch on PATH)")
    scope.add_argument("--offline", action="store_true", help="no buildbot, no romfetch, no build")
    scope.add_argument("--content-file", default=str(CONTENT_FILE),
                       help="the test content list (default: tests/campaign/content.yml)")
    scope.add_argument("--allow-unsandboxed", action="store_true",
                       help="run cores and builds without bubblewrap when it is missing (refused by default)")
    run_p = sub.add_parser("run", parents=[scope], help="one pass: cores, content, checks, rules")
    run_p.add_argument("--budget", type=parse_budget, default=6 * 3600.0,
                       help="stop starting checks after this long (6h, 90m, 3600s)")
    run_p.add_argument("--max-load-wait", type=float, default=3600,
                       help="seconds to wait for an idle host before pausing the pass")
    run_p.add_argument("--min-free-gb", type=float, default=30, help="pause below this free space")
    run_p.add_argument("--cache-cap-gb", type=float, default=20,
                       help="content the campaign fetched is evicted past this size, oldest use first")
    run_p.add_argument("--bench", action="store_true",
                       help="also time each content that boots (benchmarks only choose between variants)")
    run_p.add_argument("--dry-run", action="store_true", help="print the plan, run nothing")
    run_p.add_argument("--commit", action="store_true",
                       help="commit records, findings and each changed profile behind the gate")
    run_p.add_argument("--commit-every", type=int, default=0, metavar="N",
                       help="with --commit, also commit after every N emulators")
    refs_p = sub.add_parser("references", parents=[scope],
                            help="run the full set with PNG frames and list reference candidates")
    refs_p.add_argument("--png-dir", default=str(ROOT / "tmp" / "campaign" / "references"),
                        help="where the frames are written, one folder per core and content")
    status_p = sub.add_parser("status", help="done, failed and pending checks, and why")
    status_p.add_argument("--json", action="store_true", help="the report as JSON")
    findings_p = sub.add_parser("findings", help="profile claims the runs contradict, open for review")
    findings_p.add_argument("--all", action="store_true", help="applied and resolved too")
    findings_p.add_argument("--json", action="store_true", help="the findings as JSON")
    review_p = sub.add_parser("review", help="close an open finding after reading the code")
    review_p.add_argument("key", help="emulator/system/file/field, as `findings` prints it")
    review_p.add_argument("--status", required=True, choices=REVIEWED,
                          help="applied: the profile now says what the code does, rejected: it already did")
    review_p.add_argument("--reason", required=True,
                          help="what the code does, with its file:line at the profile's pin")
    review_p.add_argument("--set", action="append", default=[], metavar="FIELD=YAML",
                          help="with --status applied, a field to write into the entry")
    review_p.add_argument("--index", type=int, help="the entry's position when several share its name")
    sub.add_parser("gate", help="tests, schemas, verify and pack of the changed profiles")
    args = parser.parse_args(argv)

    paths = Paths.default()
    if args.command == "gate":
        return gate(paths.root, changed_profiles(paths.root))
    if args.command == "review":
        updates: dict[str, object] = {}
        for item in args.set:
            name, sep, value = item.partition("=")
            if not sep or not name:
                parser.error(f"--set {item!r}: FIELD=YAML")
            updates[name] = yaml.safe_load(value)
        try:
            line = review_finding(paths.root, args.key, args.status, args.reason, updates,
                                  args.index)
        except (ValueError, campaign_profiles.ProfileEditError) as exc:
            print(f"campaign: {exc}", file=sys.stderr)
            return 1
        print(f"{line['status']} {line['key']} [{line['id']}]")
        return 0
    if args.command == "findings":
        lines = open_findings(paths.root, args.all)
        if args.json:
            print(json.dumps(lines, indent=2))
        for line in [] if args.json else lines:
            print(f"{line['status']:8} {line['key']}: profile says {json.dumps(line['profile_says'])}, "
                  f"run shows {json.dumps(line['run_shows'])}. {line['statement']} "
                  f"[{', '.join(line['evidence'])}]")
        return 0
    settings = Settings()
    if args.command == "run":
        settings = Settings(budget=args.budget, max_load_wait=args.max_load_wait,
                            min_free_gb=args.min_free_gb, cache_cap_gb=args.cache_cap_gb,
                            romfetch=args.romfetch, network=not args.offline,
                            allow_unsandboxed=args.allow_unsandboxed, bench=args.bench)
    elif args.command == "references":
        settings = Settings(romfetch=args.romfetch, network=not args.offline,
                            allow_unsandboxed=args.allow_unsandboxed)
    if args.command in ("run", "references"):
        paths.content_file = Path(args.content_file)
    campaign = Campaign(paths, settings)
    if args.command == "status":
        report = status_report(campaign)
        print(json.dumps(report, indent=2) if args.json else render_status(report))
        return 0
    only = {item.strip() for item in args.only.split(",") if item.strip()}
    if args.command == "references":
        try:
            with host_lock(campaign.lock_path):
                listed = campaign.references(only, args.system, Path(args.png_dir))
        except autorun.LockBusy as exc:
            print(f"campaign: deferred, {exc}", file=sys.stderr)
            return 75
        print(json.dumps(listed, indent=2))
        return 0
    if args.dry_run:
        campaign.run(only, args.system, dry_run=True)
        return 0
    campaign.dirty_at_start = set(autorun.changed_files(paths.root)) if args.commit else set()

    def stop(signum: int, frame: object) -> None:
        # SIGTERM ends the pass like Ctrl-C: state saved, pass line written.
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        with host_lock(campaign.lock_path):
            current = campaign.run(only, args.system, commit_every=args.commit_every,
                                   commit=args.commit)
    except autorun.LockBusy as exc:
        print(f"campaign: deferred, {exc}", file=sys.stderr)
        return 75
    counts, _, _ = campaign.counts()
    report = {"result": current.result, "detail": current.detail, "counts": counts,
              "records": len(current.records), "findings": current.findings}
    if current.result == "refused":
        # autorun raises an alert from this key of a job's report.
        report["alert"] = current.detail
    print(json.dumps(report))
    if current.result == "refused":
        return EXIT_REFUSED
    return 75 if current.result == "paused" else 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
