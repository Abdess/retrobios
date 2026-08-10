#!/usr/bin/env python3
"""The one place that decides what a platform's native check actually does.

verify.py reports coverage and generate_pack.py decides what goes in the ZIP.
They have to reach the same verdict on the same file or the pack and the
report describe different collections. The rule they share is small:

    does the frontend read the file's bytes, or only look for the name?

Everything downstream follows from that answer. RetroArch, Lakka and RetroPie
call path_is_valid() and never open the file, so a declared hash contradicted
by the local dump is a documentation error, the file still loads, and the
builder ships it while the report flags the divergence. Batocera, Recalbox,
RetroBat, RetroDECK, RomM, ROCKNIX, MiSTer and BizHawk compare a digest, so
the same file would be rejected at runtime and shipping it would be shipping
a known failure.

Keeping the predicate here rather than in each caller is what makes
"verify.py and generate_pack.py must agree" a property of the code instead of
something a reviewer has to notice.
"""

from __future__ import annotations

DEFAULT_MODE = "existence"

#: Every verification mode a platform YAML may declare. Mirrors the enum in
#: schemas/platform.schema.json; tests/test_audit_regressions.py pins them
#: together so a new mode cannot be added to one without the other.
MODES = ("existence", "md5", "sha1")

#: The digest each content-checking mode compares. Modes absent from this map
#: do not read the file at all.
MODE_DIGEST = {"md5": "md5", "sha1": "sha1"}


def normalize(mode: str | None) -> str:
    """Return a declared mode, falling back to the schema default."""
    return mode if mode in MODES else DEFAULT_MODE


def reads_file_contents(mode: str | None) -> bool:
    """Whether the frontend opens the file rather than just finding it."""
    return normalize(mode) in MODE_DIGEST


def digest_algorithm(mode: str | None) -> str | None:
    """The hash this mode compares, or None when it compares nothing."""
    return MODE_DIGEST.get(normalize(mode))


def hash_mismatch_excludes_file(mode: str | None) -> bool:
    """Whether a local dump contradicting a declared hash must be omitted.

    True for the digest modes: the frontend would reject the file, so packing
    it ships a known failure. False for existence: the frontend never looks,
    and dropping the file over an upstream metadata error would remove
    something that works.
    """
    return reads_file_contents(mode)
