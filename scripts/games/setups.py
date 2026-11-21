"""The published setup documents: each setup's rom folders with their systems, profile and fallback keys."""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass, field

from games.fallback import FallbackTables, platform_required, shared_table
from games.folders import emulator_profile, resolve_folder
from games.inputs import FORMAT_VERSION, Inputs, load_json
from games.profileindex import Profiles
from model.romfolders import ProfileResolver, SystemResolver


@dataclass
class _SetupContext:
    resolver: SystemResolver
    cores: ProfileResolver
    profiles: Profiles
    arcade: set[str]
    inputs: Inputs
    fallbacks: FallbackTables
    manifests: dict[str, dict] = field(default_factory=dict)
    required: dict[str, dict[tuple[str, str], bool]] = field(default_factory=dict)

    def manifest(self, platform: str) -> dict | None:
        if platform and platform not in self.manifests:
            path = self.inputs.install / f"{platform}.json"
            if path.exists():
                self.manifests[platform] = load_json(path)
                self.required[platform] = platform_required(platform, self.inputs.platforms)
        return self.manifests.get(platform)


def _board_defaults(ctx: _SetupContext, row: dict,
                    fallback_keys: Callable[[str | None], list[str]] | None) -> dict:
    boards = {}
    for board, spec in sorted((row.get("board_defaults") or {}).items()):
        boards[board] = {"core": spec["core"]}
        board_profile = ctx.cores.resolve(spec["core"])
        if board_profile:
            boards[board]["profile"] = board_profile
            if board_profile in ctx.arcade:
                boards[board]["arcade"] = board_profile
        if fallback_keys:
            # A card moves between boards, and the installer reads
            # it on a computer: each board's core has its set.
            boards[board]["fallback"] = fallback_keys(board_profile)
    return boards


def _publish_folder(ctx: _SetupContext, row: dict, platform: str, manifest: dict | None,
                    counts: dict[str, int]) -> dict:
    counts["folders"] += 1
    profile = (ctx.cores.resolve(row.get("core"))
               or emulator_profile(row, platform, ctx.cores, ctx.resolver, ctx.profiles))
    resolution = resolve_folder(row, platform, profile, ctx.resolver, ctx.profiles, ctx.arcade)
    published: dict = {
        "folder": row["folder"],
        "systems": resolution.systems,
        "basis": resolution.basis,
    }
    for key in ("name", "aliases", "extensions", "files", "core", "emulator", "note"):
        if row.get(key):
            published[key] = row[key]
    if profile:
        published["profile"] = profile
        counts["profile"] += 1
    if resolution.systems:
        counts["resolved"] += 1

    fallback_keys = None
    if manifest is not None and resolution.systems:
        fallback_keys = functools.partial(ctx.fallbacks.keys, platform, manifest, ctx.required[platform],
                                          resolution.systems)
    boards = _board_defaults(ctx, row, fallback_keys)
    if boards:
        published["board_defaults"] = boards
    if profile and profile in ctx.arcade:
        published["arcade"] = profile
    elif row.get("arcade"):
        published["arcade"] = True
    if fallback_keys:
        keys = fallback_keys(profile)
        published["fallback"] = keys
        if any(ctx.fallbacks.tables[platform][k]["files"] for k in keys):
            counts["fallback"] += 1
    published["source_ref"] = row["source_ref"]
    return published


def build_setups(
    setups: dict[str, dict],
    resolver: SystemResolver,
    cores: ProfileResolver,
    profiles: Profiles,
    arcade: set[str],
    inputs: Inputs,
) -> tuple[dict[str, dict], dict[str, dict], dict]:
    """Published setup documents, fallback tables per platform, coverage."""
    ctx = _SetupContext(resolver, cores, profiles, arcade, inputs, FallbackTables(profiles))
    out: dict[str, dict] = {}
    coverage: dict[str, dict] = {}
    for setup, doc in sorted(setups.items()):
        platform = doc.get("platform") or ""
        manifest = ctx.manifest(platform)
        counts = {"folders": 0, "resolved": 0, "profile": 0, "fallback": 0}
        folders = [_publish_folder(ctx, row, platform, manifest, counts) for row in doc.get("folders", [])]
        out[setup] = {
            "format_version": FORMAT_VERSION,
            "setup": setup,
            "name": doc["name"],
            "platform": platform,
            "sources": doc["sources"],
            "roms_root": doc["roms_root"],
            "case_sensitive": doc["case_sensitive"],
            **{k: doc[k] for k in ("skip", "hidden", "media", "notes") if doc.get(k)},
            "folders": folders,
        }
        coverage[setup] = counts
    published_fallbacks = {
        platform: shared_table(platform, table) for platform, table in sorted(ctx.fallbacks.tables.items())
    }
    return out, published_fallbacks, coverage
