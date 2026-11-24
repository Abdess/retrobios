"""What the installer test modules share: install.py loaded once, loopback runs and served trees."""
from __future__ import annotations

import tests
from tests import loopback
from tests import scratch_dir

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import unittest
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
