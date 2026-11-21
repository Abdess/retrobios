"""What a campaign reads from the machine: processes in their own group, settings, paths, the child environment and the host lock."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import os
import re
import signal
import subprocess
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING, TypedDict

from unattended import worktree
import core_probe
from core import childenv, hostguard
from core.paths import DB_FILE, REPO_ROOT

if TYPE_CHECKING:
    from typing_extensions import Unpack


CONTENT_FILE = REPO_ROOT / "tests" / "campaign" / "content.yml"



NETWORK_DELAYS = (10, 60, 300)


BENCH_WARMUP = 600
BENCH_FRAMES = 1800
BENCH_REPEAT = 5
CHECK_REPEAT = 2
PROBE_TIMEOUT = 900


class Unavailable(RuntimeError):
    """A core or a piece of content the campaign cannot get."""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"




# --------------------------------------------------------------------------
# Host
# --------------------------------------------------------------------------

class PopenOptions(TypedDict, total=False):
    """The Popen arguments the campaign passes through run_group."""

    cwd: str | Path
    env: dict[str, str]
    text: bool
    stdout: int | IO[str] | IO[bytes]
    stderr: int | IO[str] | IO[bytes]


def run_group(argv: Sequence[str], *, timeout: float | None = None, check: bool = False,
              capture_output: bool = False, **kwargs: Unpack[PopenOptions]) -> subprocess.CompletedProcess:
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


BUSY_POLL = 15


def run_when_idle(argv: Sequence[str], max_wait: float, *, timeout: float | None = None,
                  env: dict[str, str] | None = None,
                  clock: Callable[[], float] = time.monotonic,
                  pause: Callable[[float], None] = time.sleep,
                  runner: Callable[..., subprocess.CompletedProcess] = run_group,
                  ) -> subprocess.CompletedProcess:
    """core_probe, run again while it refuses a busy host: every BUSY_POLL
    seconds until max_wait seconds have passed. The load threshold stays
    core_probe's own, and a timeout kills the run's whole process group."""
    started = clock()
    while True:
        proc = runner(list(argv), cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout,
                      **({"env": env} if env is not None else {}))
        if proc.returncode != core_probe.EXIT_BUSY or clock() - started >= max_wait:
            return proc
        pause(BUSY_POLL)


@dataclass
class Host:
    """What the campaign reads from the machine and the network, replaced in tests."""

    loadavg: Callable[[], tuple[float, float, float]] = os.getloadavg
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    cpu_count: int = os.cpu_count() or 1
    free_gb: Callable[[Path], float] = hostguard.free_gb
    poll: float = 60.0
    run: Callable[..., subprocess.CompletedProcess] = run_group
    urlopen: Callable[..., http.client.HTTPResponse] = urllib.request.urlopen

    @property
    def max_load(self) -> float:
        return self.cpu_count / 4


def parse_budget(text: str) -> float:
    """Seconds of a --budget value: a number with s, m or h."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smh]?)\s*", text or "")
    if not match:
        raise argparse.ArgumentTypeError(f"--budget {text!r}: a number with s, m or h")
    return float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]


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
        main = worktree.main_checkout()
        return cls(root=REPO_ROOT, home=main / ".cache" / "campaign",
                   content=main / ".cache" / "test-content", db=REPO_ROOT / DB_FILE)


ROMFETCH_PASSED = ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME")


def child_env(romfetch: bool = False) -> dict[str, str]:
    """What a program the campaign starts inherits: autorun's allowlist,
    never a token or a password. romfetch also gets its own settings
    (ROMFETCH_*), its account staying in its config file."""
    names: list[str] = [core_probe.PROBE_LOCK_ENV, core_probe.PROBE_LOCK_HELD_ENV]
    if romfetch:
        names += [k for k in os.environ if k.startswith("ROMFETCH_")] + list(ROMFETCH_PASSED)
    return childenv.safe_env(names)


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
    if os.environ.get(hostguard.LOCK_HELD_ENV):
        yield
        return
    with hostguard.global_lock(lock_path):
        yield
