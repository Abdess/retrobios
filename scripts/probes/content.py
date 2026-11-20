"""The test content of each system, fetched through romfetch and checked by hash."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from core.hashing import file_digest
from core.statefile import now_iso
from probes.host import Unavailable, child_env

if TYPE_CHECKING:
    from probes.campaign import Campaign


ROMFETCH_ENV = "RETROBIOS_ROMFETCH"


ROMFETCH_TRANSIENT = 3


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
    also_regions: tuple[str, ...] = ()

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
                also_regions=tuple(item.get("also_regions") or ()),
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
        if not path.is_file() or path.stat().st_size != item["size"] or file_digest(path) != item["sha1"]:
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
