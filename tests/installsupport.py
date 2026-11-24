"""What the installer test modules share: install.py loaded once, loopback runs, served trees, the fake repositories, cards and payloads."""
from __future__ import annotations

import tests
from tests import loopback
from tests import scratch_dir

import functools
import hashlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)


def reported(call, *args):
    """call(*args), a refusal said as the command says it: a library
    function raises it, and the command prints it."""
    try:
        return call(*args)
    except install.Refusal as refusal:
        refusal.report()
        raise


class _LoopbackRun:
    """install.py against the repository's own manifests over loopback."""

    def serve(self, test: unittest.TestCase) -> dict:
        base = loopback.serve(test, REPO_ROOT)
        self.home = scratch_dir(test)
        return {
            **os.environ, "HOME": str(self.home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": base,
        }


def _install_run(env: dict, *argv: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "install.py", *argv], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False, **kwargs,
    )


class _FakeResponse:
    """What urlopen returns, serving one payload from its start."""

    def __init__(self, payload: bytes) -> None:
        self.status = 200
        self.headers = {"Content-Length": str(len(payload))}
        self._body = io.BytesIO(payload)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)


class _SyntheticTree:
    """A served tree of four BIOS files over loopback, one with no system,
    and a BIOS folder holding one of them, another with other bytes, and
    neither of the last two."""

    FILES = {
        "bios/A/a.bin": b"alpha" * 20,
        "bios/A/b.bin": b"bravo" * 30,
        "bios/B/c.bin": b"charlie" * 10,
        "bios/X/d.bin": b"delta" * 5,
    }

    def serve_tree(self, test: unittest.TestCase) -> dict:
        root = scratch_dir(test)
        files = []
        for path, data in self.FILES.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_bytes(data)
            name = Path(path).name
            systems = {"a.bin": ["sys-a"], "b.bin": ["sys-a"], "c.bin": ["sys-b"]}.get(name)
            entry = {"dest": name, "repo_path": path, "size": len(data),
                     "sha1": hashlib.sha1(data).hexdigest(), "cores": None}
            if systems:
                entry["systems"] = systems
            files.append(entry)
        manifest = {
            "manifest_version": 2, "platform": "retroarch", "display_name": "RetroArch",
            "files": files, "system_names": {"sys-a": ["alpha"]},
            "omitted_files": [{"dest": "e.bin", "name": "e.bin", "system": "sys-b",
                               "required": True, "reason": "not_found",
                               "systems": ["sys-b"]}],
        }
        (root / "install").mkdir()
        (root / "install" / "retroarch.json").write_text(json.dumps(manifest))

        base = loopback.serve(test, root)
        self.home = scratch_dir(test)
        self.bios = self.home / "bios"
        self.bios.mkdir()
        (self.bios / "a.bin").write_bytes(self.FILES["bios/A/a.bin"])
        (self.bios / "b.bin").write_bytes(b"other bytes")
        return {
            **os.environ, "HOME": str(self.home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": base,
        }


def _events(proc: subprocess.CompletedProcess) -> list[dict]:
    """The --events stream, every stdout line a JSON object."""
    return [json.loads(line) for line in proc.stdout.splitlines()]


class FakeRepository:
    """A loopback copy of the repository: one manifest and its payloads."""

    PAYLOADS = {
        "scph5500.bin": (b"jp bios", ["sony-playstation"], ["japan"], None),
        "scph5501.bin": (b"us bios", ["sony-playstation"], ["north-america"], None),
        "gba_bios.bin": (b"gba bios", ["nintendo-gba"], None, None),
        "pcsx/extra.bin": (b"pcsx", ["sony-playstation"], None, ["pcsx_rearmed"]),
        "mgba/extra.bin": (b"mgba", ["nintendo-gba"], None, ["mgba"]),
    }

    def __init__(self, selection: bool = True):
        self.selection = selection

    def __enter__(self) -> FakeRepository:
        self.root = Path(tempfile.mkdtemp())
        (self.root / "install").mkdir()
        (self.root / "bios").mkdir()
        files = []
        for name, (payload, systems, regions, cores) in self.PAYLOADS.items():
            stored = name.replace("/", "_")
            (self.root / "bios" / stored).write_bytes(payload)
            entry = {
                "dest": name,
                "sha1": hashlib.sha1(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "repo_path": f"bios/{stored}",
                "cores": cores,
            }
            if self.selection:
                entry["systems"] = systems
                if regions:
                    entry.update(regions=regions, region_system_groups=systems)
            files.append(entry)
        manifest = {"manifest_version": 2, "platform": "retroarch", "files": files}
        (self.root / "install" / "retroarch.json").write_text(json.dumps(manifest))
        handler = functools.partial(loopback.Quiet, directory=str(self.root))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.dest = self.root / "dest"
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.root, ignore_errors=True)

    def env(self) -> dict:
        env = dict(os.environ)
        env["RETROBIOS_BASE_URL"] = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return env

    def command(self, *options: str) -> list[str]:
        return [sys.executable, str(REPO_ROOT / "install.py"), "--platform",
                "retroarch", "--dest", str(self.dest), *options]

    def run(self, *options: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.command(*options), env=self.env(), capture_output=True,
            text=True, timeout=60, check=False, stdin=subprocess.DEVNULL,
        )

    def installed(self) -> list[str]:
        if not self.dest.exists():
            return []
        return sorted(
            p.relative_to(self.dest).as_posix()
            for p in self.dest.rglob("*") if p.is_file()
        )


INDEX = REPO_ROOT / "install" / "launchers" / "index.json"


def make_card(root: Path, system: str) -> Path:
    """A card as each system leaves it, and the BIOS folder on it."""
    bios = _card_files(root, system)
    bios.mkdir(parents=True, exist_ok=True)
    return bios


def _card_files(root: Path, system: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if system == "muOS":
        (root / "MUOS" / "bios").mkdir(parents=True)
        return root / "MUOS" / "bios"
    if system == "KNULLI":
        (root / "system").mkdir()
        (root / "system" / "batocera.conf").write_text("system.hostname=KNULLI\n")
        return root / "bios"
    if system == "ROCKNIX":
        (root / ".config" / "system" / "configs").mkdir(parents=True)
        (root / ".config" / "system" / "configs" / "system.cfg").write_text(
            "root.password=rocknix\n")
        return root / "roms" / "bios"
    if system == "Onion":
        (root / ".tmp_update" / "onionVersion").mkdir(parents=True)
        (root / ".tmp_update" / "onionVersion" / "version.txt").write_text("4.3.1\n")
        return root / "BIOS"
    if system == "spruceOS":
        (root / "spruce").mkdir()
        return root / "BIOS"
    if system == "MinUI":
        (root / ".system").mkdir()
        (root / ".system" / "version.txt").write_text("MinUI-20250101\n")
        return root
    raise ValueError(system)


class AppRepository(FakeRepository):
    """The fake repository with the launcher list and every file it names,
    and the BIOS lists of the systems whose cards are tried."""

    def __enter__(self) -> AppRepository:
        super().__enter__()
        index = json.loads(INDEX.read_text(encoding="utf-8"))
        (self.root / "install" / "launchers").mkdir()
        (self.root / "install" / "launchers" / "index.json").write_text(json.dumps(index))
        for launcher in index["launchers"].values():
            for entry in launcher.get("files", launcher.get("members", [])):
                if "repo_path" in entry:
                    target = self.root / entry["repo_path"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(REPO_ROOT / entry["repo_path"], target)
        base = json.loads((self.root / "install" / "retroarch.json").read_text())
        for plat in ("knulli", "rocknix", "minui"):
            (self.root / "install" / f"{plat}.json").write_text(
                json.dumps({**base, "platform": plat}))
        return self

    def card(self, system: str) -> tuple[Path, Path]:
        root = self.root / "cards" / system
        return root, make_card(root, system)

    def tamper(self, repo_path: str) -> None:
        """One byte changed, the size kept: only the hash tells."""
        path = self.root / repo_path
        data = bytearray(path.read_bytes())
        data[-1] ^= 0x20
        path.write_bytes(bytes(data))

    def cli(self, *options: str, env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), *options],
            env={**self.env(), **(env or {})}, capture_output=True, text=True,
            timeout=120, check=False, stdin=subprocess.DEVNULL)


US = b"us bios " * 64
JP = b"jp bios " * 64
EU = b"eu bios " * 64
GBA = b"gba bios" * 32
EXTRA = b"pcsx extra"


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _entry(dest: str, data: bytes, systems: list[str], **fields) -> dict:
    return {
        "dest": dest, "sha1": _sha1(data), "size": len(data),
        "repo_path": f"bios/{dest.replace('/', '_')}", "cores": None,
        "systems": systems, **fields,
    }


def manifest() -> dict:
    """A small RetroArch list: two regions of one BIOS, a core file with a
    second revision, a file in a subfolder."""
    return {
        "manifest_version": 2,
        "platform": "retroarch",
        "files": [
            _entry("scph5501.bin", US, ["sony-playstation"], regions=["north-america"]),
            _entry("scph5500.bin", JP, ["sony-playstation"], regions=["japan"]),
            _entry("gba_bios.bin", GBA, ["nintendo-gba"]),
            _entry("pcsx/extra.bin", EXTRA, ["sony-playstation"], cores=["pcsx_rearmed"],
                   alternatives=[{"sha1": _sha1(EU), "size": len(EU),
                                  "repo_path": "bios/eu", "cores": ["beetle_psx"]},
                                 {"sha1": _sha1(EXTRA), "size": len(EXTRA),
                                  "repo_path": "bios/x", "cores": ["pcsx_rearmed"]}]),
        ],
        "system_cores": {"sony-playstation": ["beetle_psx", "pcsx_rearmed"],
                         "nintendo-gba": ["mgba"]},
    }


PAYLOAD = {"scph5501.bin": US, "scph5500.bin": JP, "gba_bios.bin": GBA,
           "pcsx/extra.bin": EXTRA}


def _offline_env() -> dict:
    """An environment where any request the installer makes is refused."""
    env = dict(os.environ)
    env["RETROBIOS_BASE_URL"] = f"http://127.0.0.1:{loopback.closed_port()}"
    env["HTTPS_PROXY"] = env["HTTP_PROXY"] = f"http://127.0.0.1:{loopback.closed_port()}"
    return env


class Scratch(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.dest = self.root / "system"
        self.list = self.root / "retroarch.json"
        self.list.write_text(json.dumps(manifest()))

    def run_installer(self, *options: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(self.dest), *options],
            env=_offline_env(), capture_output=True, text=True, timeout=120,
            check=False, stdin=subprocess.DEVNULL,
        )

    def place(self, relative: str, data: bytes) -> Path:
        path = self.dest / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def check(self) -> str:
        proc = self.run_installer("--check", "--manifest", str(self.list), "--verbose")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        return proc.stdout

    def complete(self, *skip: str) -> None:
        for name, data in PAYLOAD.items():
            if name not in skip:
                self.place(name, data)


def _pack(directory: Path, name: str, members: dict[str, bytes]) -> Path:
    """A pack as generate_pack writes one: the files and a manifest.json."""
    listed = [{"path": path, "sha1": _sha1(data), "md5": hashlib.md5(data).hexdigest(),
               "size": len(data), "status": "verified", "name": path.rsplit("/", 1)[-1]}
              for path, data in members.items()]
    path = directory / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for member, data in members.items():
            archive.writestr(member, data)
        archive.writestr("README.txt", b"read me\n")
        archive.writestr("manifest.json", json.dumps({"files": listed}))
    return path
