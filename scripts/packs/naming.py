"""The names of pack archives and manifests, built from every narrowing."""

from __future__ import annotations

import hashlib
import os
import re

from model import region
from model.platforms import load_platform_config
from model.registry import list_release_pack_platforms
from model.systems import MANUFACTURER_PREFIXES
from model.targets import build_target_cores_cache, canonical_target_name, platform_files_target
from packs import parts as packs_parts
from resolve.grouping import group_identical_platforms


def pack_narrowings(
    source: str,
    regions: list[str] | None,
    target_name: str | None,
    one_per_slot: bool,
    required_only: bool,
    standalone: bool = False,
    no_game_data: bool = False,
) -> list[tuple[str, str]]:
    """Every dimension that narrows a pack, as (filename tag, plain label).

    The pack name and the pack README are both built from this list, so a new
    way of narrowing a pack cannot reach users nameless or unannounced. Order
    is the filename order and must not change: it is what existing archives
    are called.
    """
    applied: list[tuple[str, str]] = []
    if source == "platform":
        applied.append(("_Platform", "only what the platform declares"))
    elif source == "truth":
        applied.append(("_Truth", "only what emulator profiles require"))
    if regions:
        pretty = ", ".join(
            " ".join(w.title() for w in slug.split("-")) for slug in regions
        )
        applied.append(
            (f"_{region.region_tag(regions)}", f"region priority {pretty}")
        )
    if target_name:
        applied.append(
            (f"_{_target_tag(target_name)}", f"cores available on {target_name}")
        )
    if one_per_slot:
        applied.append(("_OnePerSlot", "one BIOS per system and region"))
    if standalone:
        applied.append(("_Standalone", "standalone mode files only"))
    if required_only:
        applied.append(("_Required", "required files only"))
    if no_game_data:
        applied.append(("_NoGameData", "firmware only, game data left out"))
    return applied


def _target_tag(target_name: str) -> str:
    """Filename tag for a hardware target.

    Without it a targeted pack takes the same name as the full one and
    overwrites it.
    """
    return "".join(
        part.title() for part in re.split(r"[-_\s]+", target_name.strip()) if part
    )


def platform_target(
    platform_name: str, target: str | None, platforms_dir: str
) -> str | None:
    """The target as this platform files it, the name its artifacts carry.

    Named once for the whole run, a target two platforms file differently
    (rpi4: Batocera's bcm2711, Recalbox's rpi4_64) kept the typed name under
    --all and took the platform's own under --platform, so --verify-packs
    looked for a pack the --all build had named otherwise. A platform that
    does not file the target is packed whole under --all, and its name
    claims no narrowing: BizHawk_..._Switch_BIOS_Pack.zip was the full pack.
    """
    if not target or not platform_files_target(platform_name, target, platforms_dir):
        return None
    return canonical_target_name([platform_name], target, platforms_dir)


def system_display_name(system_id: str) -> str:
    """A system id as a pack file name writes it, its maker prefix dropped."""
    s = system_id.lower().replace("_", "-")
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    return "_".join(p.title() for p in s.split("-") if p)


def system_tag(system_filter: list[str] | None) -> str:
    """Filename tag for a pack limited to some systems, empty for all."""
    if not system_filter:
        return ""
    display_parts = [system_display_name(sid) for sid in system_filter]
    return "_" + bounded_join(display_parts, system_filter)


# A system list long enough to push a pack name past this falls back to the
# first system, a count and a digest of the list.
MAX_SYSTEM_TAG_BYTES = 120


def bounded_join(parts: list[str], keys: list[str]) -> str:
    """Parts joined while they fit, else the first, a count and a digest.

    Thirty systems joined made a 261-byte file name and the ZIP could not
    be opened. The digest keeps two different selections apart. The joiner
    is one no part holds: with "_", sega-dreamcast + arcade and
    sega-dreamcast-arcade both named Dreamcast_Arcade, and the second build
    replaced the first.
    """
    joined = "+".join(parts)
    if len(joined.encode("utf-8")) <= MAX_SYSTEM_TAG_BYTES:
        return joined
    digest = hashlib.sha1("\n".join(sorted(keys)).encode("utf-8")).hexdigest()[:8]
    return f"{parts[0]}_and_{len(parts) - 1}_more_{digest}"


_UNSAFE_IN_NAME = re.compile(r'[/\\:*?"<>|]')


def file_name_part(text: str, space: str = "") -> str:
    """A display name made safe to stand in a file name.

    'FinalBurn Neo (CPS-1/CPS-2)' named a directory that did not exist, and a
    Windows user cannot write ':' or '?' either.
    """
    return _UNSAFE_IN_NAME.sub("-", text.replace(" ", space))


def platform_pack_stem(
    group_platforms: list[str], representative: str, platforms_dir: str
) -> str:
    """Platform part of a pack name, version included.

    A group of identical platforms shares one pack named after all of them,
    and the builder and --verify-packs both read the name from here.
    """
    rep_cfg = load_platform_config(representative, platforms_dir)
    version = rep_cfg.get("version", rep_cfg.get("dat_version", ""))
    version_tag = f"_{file_name_part(str(version))}" if version else ""
    return platform_pack_prefix(group_platforms, representative, platforms_dir) + version_tag


def platform_pack_prefix(
    group_platforms: list[str], representative: str, platforms_dir: str
) -> str:
    """Platform part of a pack name without the version.

    The site reads a pack's version back by removing this prefix: a version
    may hold an underscore (AmberELEC prerelease-20261019_1835).
    """
    if len(group_platforms) <= 1:
        rep_cfg = load_platform_config(representative, platforms_dir)
        return file_name_part(rep_cfg.get("platform", representative), "_")
    names = [
        load_platform_config(p, platforms_dir).get("platform", p)
        for p in group_platforms
    ]
    return "_".join(file_name_part(n) for n in names)


def platform_pack_name(
    platform_name: str,
    platforms_dir: str,
    narrowings: list[tuple[str, str]],
    system_filter: list[str] | None,
    pack_name: str | None = None,
    group: list[str] | None = None,
) -> str:
    """File name of a platform pack: stem, narrowing tags, system tag.

    A caller naming the pack itself (a --split part) is taken at its word.
    A pack shared by a group of identical platforms is named after the
    group, platform_name being its representative.
    """
    if pack_name:
        return pack_name
    stem = platform_pack_stem(group or [platform_name], platform_name, platforms_dir)
    tags = "".join(tag for tag, _label in narrowings)
    return f"{stem}{tags}_BIOS_Pack{system_tag(system_filter)}.zip"


# A file name holds 255 bytes on every filesystem a pack is written to,
# and the margin leaves room for the split part suffix and a scratch prefix.
MAX_PACK_NAME_BYTES = 200


def bounded_pack_name(display_names: list[str], keys: list[str], suffix: str) -> str:
    """The emulator pack's file name, its emulators joined while they fit.

    Past the limit the name keeps the first emulator, says how many more the
    pack holds, and carries a digest of the selection so two different
    selections never share a file.
    """
    joined = "_".join(display_names) + suffix
    if len(joined.encode("utf-8")) <= MAX_PACK_NAME_BYTES:
        return joined
    digest = hashlib.sha1("\n".join(sorted(keys)).encode("utf-8")).hexdigest()[:8]
    return f"{display_names[0]}_and_{len(display_names) - 1}_more_{digest}{suffix}"


def expected_pack_names(
    platforms: list[str],
    platforms_dir: str,
    regions: list[str] | None,
    target_name: str | None,
    variants: tuple[tuple[str, bool], ...] = (("full", False),),
    no_game_data: bool = False,
) -> dict[str, set[str]]:
    """Exact pack file names --verify-packs may check, per platform.

    Rebuilt from the name builder, never matched by substring: a substring
    picks the full pack when a regional or targeted one was asked for, or a
    narrowed pack when the full one was. A platform answers to its own name
    and to the name of the group it shares a pack with. ``variants`` lists
    the (source, required_only) combinations the run built.
    """
    def narrowings(platform_name: str) -> list[list[tuple[str, str]]]:
        named = platform_target(platform_name, target_name, platforms_dir)
        return [
            pack_narrowings(source, regions, named, False, required, no_game_data=no_game_data)
            for source, required in variants
        ]

    names: dict[str, set[str]] = {
        p: {
            platform_pack_name(p, platforms_dir, narrowed, None)
            for narrowed in narrowings(p)
        }
        for p in platforms
    }
    # Groups depend on which platforms a run built: the release packs of
    # --all.
    pool = list_release_pack_platforms(platforms_dir)
    cache = None
    if target_name:
        try:
            cache, pool = build_target_cores_cache(
                pool, target_name, platforms_dir, is_all=True
            )
        except ValueError:
            # No platform has the target: no pack was built under it.
            return names
    for group, representative in group_identical_platforms(
        pool, platforms_dir, cache
    ):
        if len(group) < 2:
            continue
        for narrowed in narrowings(representative):
            name = platform_pack_name(representative, platforms_dir, narrowed, None, group=group)
            for p in group:
                if p in names:
                    names[p].add(name)
    return names


def _content_narrowing_tags() -> tuple[str, ...]:
    """Tags naming a pack that holds fewer files than the platform declares.

    Read from the name builder rather than retyped, so the two cannot drift.
    Region and target are absent on purpose: both are handed to the check
    itself, which narrows its expectation instead of skipping it.
    """
    # (source, one_per_slot, required_only), one dimension at a time.
    dimensions = (
        ("platform", False, False),
        ("truth", False, False),
        ("full", True, False),
        ("full", False, True),
    )
    tags: list[str] = []
    for source, one_per_slot, required_only in dimensions:
        tags.extend(
            tag
            for tag, _label in pack_narrowings(source, None, None, one_per_slot, required_only)
        )
    return tuple(tags)


_CONTENT_NARROWING_TAGS = _content_narrowing_tags()


def narrows_contents(pack_name: str) -> bool:
    """True when a pack holds fewer files than the platform declares.

    A source-restricted or required-only build is narrower by design, so the
    full platform expectation does not apply to it and conformance is skipped.
    Region is not listed: the region filter is passed to the check itself, and
    a hardware target is passed the same way.
    """
    return any(f"{tag}_" in pack_name for tag in _CONTENT_NARROWING_TAGS)


def pack_variant(pack_name: str) -> tuple[str, bool] | None:
    """The (source, required_only) a pack was built as, read from its name.

    None for a one-per-slot pack, whose slot choice the check does not
    replay. The tags come from the name builder, as for narrows_contents.
    """
    def tagged(**dimension: object) -> bool:
        tags = [
            tag for tag, _label in pack_narrowings(
                str(dimension.get("source", "full")), None, None,
                bool(dimension.get("one_per_slot", False)),
                bool(dimension.get("required_only", False)),
            )
        ]
        return all(f"{tag}_" in pack_name for tag in tags)

    if tagged(one_per_slot=True):
        return None
    source = next(
        (s for s in ("platform", "truth") if tagged(source=s)), "full"
    )
    return source, tagged(required_only=True)


def pack_archives(output_dir: str) -> list[str]:
    """The ZIPs of a directory that are packs.

    A part of a split pack holds a share of a platform by design and was
    checked against the whole when it was cut: judged as a pack it would
    fail conformance, and injecting a manifest would change published bytes.
    Every name the builder gives holds `_BIOS_Pack`, then the system tag of
    a --system platform pack (`_BIOS_Pack_Playstation.zip`): build_port.py
    wrote its launcher archives (RetroBIOS.zip) to the same dist/, and
    taking every ZIP rewrote them with a manifest after build_port had
    printed their hashes.
    """
    return sorted(
        name
        for name in os.listdir(output_dir)
        if _PACK_NAME.search(name) and not packs_parts.is_part(name)
    )


_PACK_NAME = re.compile(r"_BIOS_Pack(?:_[^/]+)?\.zip$")
