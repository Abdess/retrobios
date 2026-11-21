"""Source citations that name no code, or a place no repository holds."""

from __future__ import annotations

import re
from pathlib import Path

import core.paths
from model.sourceref import split_source_ref


_CODE_SUFFIXES = frozenset(
    ["c", "cc", "cpp", "cxx", "c++", "h", "hh", "hpp", "hxx", "inc", "inl", "ipp", "m", "mm", "mjs", "cjs", "js", "jsx", "ts", "tsx", "py", "cs", "java", "kt", "go", "rs", "lua", "pas", "pp", "asm", "s", "sh", "bash", "zsh", "ps1", "bat", "cmd", "vbs", "swift", "d", "zig", "nim", "qml", "qc", "rb", "pl", "php", "scala", "ml", "hs", "dart", "vue", "ino", "z80", "smali"]
)


_CODE_FILE = re.compile(r"(?<=[\w+-])\.([A-Za-z0-9+]+)\b")


# A compiled image: a part that names one has to say where in it the file
# is read, an address, a decompiled function or an IL method.
# A name under a directory is a file of the tree it sits in, and a further
# extension (.dll.map) makes it another file.
_BINARY_FILE = re.compile(
    r"(?<![\w/+.-])[\w+.-]+\.(?:so|dll|exe|dylib|dex|elf|nro|xex)(?:\.\d+)*(?![\w.-]*\w)",
    re.IGNORECASE,
)


_BINARY_EVIDENCE = re.compile(
    r"\b0x[0-9a-fA-F]+\b"
    r"|\b(?:FUN|sub|thunk|LAB)_[0-9a-fA-F]+\b"
    r"|\bIL_[0-9a-fA-F]{4}\b"
    r"|::|\.\.c?ctor\b"
    r"|\b[A-Za-z_][\w.$]*\("
)


# Profiles whose files cite no published code. Each reason says why the
# check cannot apply yet.
DATA_ONLY_REF_EXCEPTIONS: dict[str, str] = {}


def _ref_cites_code(ref: str) -> bool:
    """A source_ref cites a source file or a place in a compiled image.

    A part naming a binary without an address, a decompiled function or an
    IL method says only that the binary exists: "import directory",
    "string table" and "readelf -d" are not the code that reads a file.
    """
    cited = False
    for part in split_source_ref(ref):
        located = bool(_BINARY_EVIDENCE.search(part.raw)) or any(
            suffix.lower() in _CODE_SUFFIXES for suffix in _CODE_FILE.findall(part.raw)
        )
        if _BINARY_FILE.search(part.raw) and not located:
            return False
        cited = cited or located
    return cited


def data_only_source_refs(path: Path, document: object) -> list[str]:
    """A files[] source_ref that cites only data or build files.

    A data file is evidence that the emulator reads a file only once the
    code that ships and parses it is cited too: iwadinfo.txt names the
    IWADs, d_iwad.cpp is what reads it. 655 entries in 27 profiles cited
    the table alone, and six of them named a file no code opens.
    """
    if not isinstance(document, dict) or path.stem in DATA_ONLY_REF_EXCEPTIONS:
        return []
    out: list[str] = []
    for index, entry in enumerate(document.get("files") or []):
        if not isinstance(entry, dict) or not entry.get("source_ref"):
            continue
        refs = entry["source_ref"]
        out.extend(
            f"{path.relative_to(core.paths.REPO_ROOT)}: files[{index}] ({entry.get('name')}) "
            f"source_ref cites no code that reads the file: {ref}"
            for ref in (refs.values() if isinstance(refs, dict) else [refs])
            if ref and not _ref_cites_code(str(ref))
        )
    return out


UNREACHABLE_REF = re.compile(
    r"(?:^|[\s,;(])(?:tmp/|/|[A-Za-z]:[\\/]|\.{1,2}/)[\w.\\/+-]*[\w+-]:\d+(?:-\d+)?"
)


def unreachable_citations(path: Path, document: object) -> list[str]:
    """Refs naming a place no repository can hold.

    A citation is read against a revision of a declared repository, so a
    scratch directory, an absolute path or one climbing out of the tree can
    never resolve and never will. kenji-nx carried tmp/es-de/ANDROID.md:470,
    a path from whoever profiled it, which profile_sync could only report
    missing forever.
    """
    out: list[str] = []
    stack: list[object] = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            out.extend(
                f"{path.relative_to(core.paths.REPO_ROOT)}: citation names a path outside "
                f"any repository: {match.group().strip(' ,;(')}"
                for match in UNREACHABLE_REF.finditer(node)
            )
    return out


DOUBLED_PATH = re.compile(r"((?:[\w.-]+/){2,})\1")


def doubled_paths(path: Path) -> list[str]:
    """A citation whose directory is written twice in a row.

    Read from the raw text, comments included: primehack's note on the
    Realtek loader cited Source/Core/Core/IOS/USB/Bluetooth/ twice over, a
    path no revision holds, in a comment the parsed document never shows.
    """
    out: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = DOUBLED_PATH.search(line)
        if match:
            out.append(
                f"{path.relative_to(core.paths.REPO_ROOT)}:{number}: citation repeats its "
                f"directory: {match.group(1)}"
            )
    return out
