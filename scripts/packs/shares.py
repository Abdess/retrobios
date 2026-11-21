"""The files a platform's cores add to its pack, placed, held or missing, as verify counts them."""

from __future__ import annotations

from dataclasses import dataclass


def split_undeclared(undeclared: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Game data, firmware the pack places, firmware it holds but cannot place.

    Everything that is not game data is firmware the core loads, archives
    included: a bios_zip sat in neither list, so a required one that was
    missing was never printed.
    """
    game_data = [u for u in undeclared if u.get("category", "bios") == "game_data"]
    firmware = [u for u in undeclared if u.get("category", "bios") != "game_data"]
    unplaced = [u for u in firmware if u["in_repo"] and not u.get("in_pack", True)]
    placed = [u for u in firmware if u.get("in_pack", True)]
    return game_data, placed, unplaced


def pack_shares(result: dict) -> tuple[int, int]:
    """The core files and the game data a platform's pack carries, by the report.

    The builder's count, one file per pack path, when the platform pass
    replayed it. Counting entries said 1130 for RetroArch, 48 more than the
    pack holds: rom.key alone was claimed by three Amiga cores.
    """
    packed = result.get("packed_extras")
    if packed is not None:
        return packed["bios"], packed["game_data"]
    game_data, bios_files, _unplaced = split_undeclared(result.get("undeclared_files", []))
    return (
        sum(1 for u in bios_files if u["in_repo"]),
        sum(1 for u in game_data if u["in_repo"] and u.get("in_pack", True)),
    )


def core_required_missing(bios_files: list[dict]) -> list[dict]:
    """Core files a core cannot run without, absent from the collection.

    A file bundled with the emulator (DaedalusX64's n64.psh, the shader
    library its renderer installs beside the binary) arrives with it: the
    collection does not hold it by design, and listing it as missing sent
    readers after a file every install already has.
    """
    return [
        u
        for u in bios_files
        if u["required"] and not u["in_repo"] and not u.get("hle_fallback")
        and not u.get("bundled")
    ]


@dataclass(frozen=True)
class CoreShares:
    """One platform's core files and game data, sorted the way verify reports them."""

    in_pack: int
    required_missing: list[dict]
    hle_missing: list[dict]
    optional_missing: list[dict]
    bundled: list[dict]
    unplaced: list[dict]
    game_data: list[dict]
    game_data_packed: int

    @property
    def game_data_missing(self) -> list[dict]:
        return [u for u in self.game_data if not u["in_repo"]]

    @property
    def game_data_unplaced(self) -> list[dict]:
        return [u for u in self.game_data if u["in_repo"] and not u.get("in_pack", True)]

    @property
    def packed(self) -> int:
        """Core files and game data the pack carries."""
        return self.in_pack + self.game_data_packed

    @property
    def missing(self) -> int:
        """Core files and game data the collection lacks, bundled ones apart."""
        return (len(self.required_missing) + len(self.hle_missing)
                + len(self.optional_missing) + len(self.game_data_missing))

    @property
    def held_unplaced(self) -> int:
        """Core files and game data held but left out of the pack."""
        return len(self.unplaced) + len(self.game_data_unplaced)


def core_shares(result: dict) -> CoreShares:
    """What a verify result says of the files its cores add to the pack."""
    undeclared = result.get("undeclared_files", [])
    game_data, bios_files, unplaced = split_undeclared(undeclared)
    # A file installed with its emulator is never collected, firmware or
    # game data, required or not: cross_reference counts it apart. The
    # firmware already left the pack lists (_mark_unplaced), the game data
    # did not, and Abuse's three bundled data files read as missing.
    bundled = [u for u in undeclared if not u["in_repo"] and u.get("bundled")]
    game_data = [u for u in game_data if u["in_repo"] or not u.get("bundled")]
    in_pack, game_data_packed = pack_shares(result)
    return CoreShares(
        in_pack=in_pack,
        required_missing=core_required_missing(bios_files),
        hle_missing=[
            u for u in bios_files
            if u["required"] and not u["in_repo"] and u.get("hle_fallback")
        ],
        optional_missing=[u for u in bios_files if not u["required"] and not u["in_repo"]],
        bundled=bundled,
        unplaced=unplaced,
        game_data=game_data,
        game_data_packed=game_data_packed,
    )
