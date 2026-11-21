"""Whether a collection file ships executable, read from its header."""

from __future__ import annotations

# A program (RetroDECK's pico8, Voxatron's vox) has to stay runnable once
# extracted or installed. The git mode cannot say: hundreds of MAME archives
# carry an execute bit nothing reads, and the Lindbergh segaboot is an ELF
# committed without one.
_PROGRAM_MAGIC = (
    b"\x7fELF",
    b"#!",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)


def ships_executable(path: str) -> bool:
    """An ELF or Mach-O binary, or a script with an interpreter line."""
    with open(path, "rb") as handle:
        head = handle.read(4)
    return any(head.startswith(magic) for magic in _PROGRAM_MAGIC)
