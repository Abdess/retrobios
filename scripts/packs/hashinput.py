"""The hashes --from-md5 and --from-md5-file name, read and checked."""

from __future__ import annotations

import re

# Digest length in hex digits -> kind. A 29-digit MD5 is a value cut short,
# looked up as the resolver looks one up (cut_md5_owner).
_HASH_KINDS = {8: "crc32", 29: "md5", 32: "md5", 40: "sha1", 64: "sha256"}
_HEX_DIGITS = re.compile(r"[0-9a-f]+")
_WORD = re.compile(r"[0-9A-Za-z]+")
ACCEPTED_HASHES = (
    "CRC32 (8 hex digits), MD5 (32, or the 29 Batocera writes), "
    "SHA-1 (40) or SHA-256 (64)"
)


def _detect_hash_type(h: str) -> str | None:
    """The digest a hex string is, by its length, or None."""
    return _HASH_KINDS.get(len(h))


def _hash_token(token: str) -> tuple[str, str] | None:
    """(kind, value) when a token is a whole digest of a known length."""
    value = token.strip().lower().removeprefix("*").removeprefix("0x")
    kind = _detect_hash_type(value)
    if kind and _HEX_DIGITS.fullmatch(value):
        return kind, value
    return None


def _refuse(rejected: list[str]) -> None:
    shown = ", ".join(rejected[:5]) + (", ..." if len(rejected) > 5 else "")
    raise ValueError(f"not a hash: {shown}. Accepted: {ACCEPTED_HASHES}")


def parse_hash_input(raw: str) -> list[tuple[str, str]]:
    """Parse a comma-separated hash string into (type, hash) tuples.

    A part that is no digest is refused rather than dropped: a 12-digit
    value was looked up as an MD5 and reported NOT FOUND, and a SHA-256
    vanished without a word.
    """
    results: list[tuple[str, str]] = []
    rejected: list[str] = []
    for part in raw.split(","):
        if not part.strip():
            continue
        parsed = _hash_token(part)
        if parsed:
            results.append(parsed)
        else:
            rejected.append(part.strip())
    if rejected:
        _refuse(rejected)
    return results


def parse_hash_file(path: str) -> list[tuple[str, str]]:
    """Parse a hash file: one hash per line, alone or beside a file name as
    md5sum writes it, ``#`` for comments. A line holding no digest is
    refused with its line number."""
    results: list[tuple[str, str]] = []
    rejected: list[str] = []
    with open(path) as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = next(
                (h for h in map(_hash_token, _WORD.findall(line)) if h), None
            )
            if parsed:
                results.append(parsed)
            else:
                rejected.append(f"line {number} ({line[:40]})")
    if rejected:
        _refuse(rejected)
    return results
