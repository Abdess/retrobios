"""Game sets read from the driver code of the MAME versions whose DAT the code moved past."""

from __future__ import annotations

import ast
import functools
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .arcade_sets import SetEntry
from .base_scraper import BlobMismatchError, download
from .clex import DriverSourceError, blank_comments, call_args, call_span
from .dat_fetch import api_json
from core.hashing import git_blob_sha


# --- MAME 0.37 and 0.78 driver source (mame2000, mame2003, mame2003-plus) ----

# driver.h at each pin: NAME is argument 1 and PARENT argument 2 in every
# form, and a BIOS set carries NOT_A_DRIVER in its flags.
_GAME_MACRO = re.compile(r"\b(GAME|GAMEX|GAMEC|GAMECX|GAMEB|GAMEBX)\s*\(")
_DRIVER_ENTRY = re.compile(r"\bDRIVER\s*\(\s*(\w+)\s*\)")
_ROM_START = re.compile(r"\bROM_START\s*\(\s*(\w+)\s*\)(.*?)\bROM_END\b", re.S)
_ROM_LOAD = re.compile(r"\bROMX?_LOAD\w*\s*\(")
_DISK_IMAGE = re.compile(r"\bDISK_IMAGE\w*\s*\(")
_ROM_START_HEAD = re.compile(r"\bROM_START\s*\(")
_DIRECTIVE = re.compile(r"^[ \t]*#[ \t]*(\w+)[ \t]*(.*)$")
_MACRO_HEAD = re.compile(r"(\w+)(\([^)]*\))?[ \t]*(.*)")
_CONDITION_TOKEN = re.compile(
    r"\s*(?:(0[xX][0-9a-fA-F]+|\d+)[uUlL]*|(defined)|([A-Za-z_]\w*)"
    r"|(&&|\|\||==|!=|<=|>=|<<|>>|[!<>()+\-*/%~&|^]))"
)
_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")
_INCLUDE = re.compile(r'"([^"]+)"')


def _condition_value(expr: str, defines: dict[str, str], depth: int = 0) -> int:
    """An ``#if`` expression the way the C preprocessor reads it: a name not
    defined is 0, a defined name is its value."""
    python: list[str] = []
    position = 0
    expr = expr.strip()
    while position < len(expr):
        match = _CONDITION_TOKEN.match(expr, position)
        if not match:
            raise DriverSourceError(f"#if {expr}: cannot read")
        number, defined, name, operator = match.groups()
        position = match.end()
        if number:
            python.append(str(int(number, 0)))
        elif defined:
            target = re.match(r"\s*\(?\s*(\w+)\s*\)?", expr[position:])
            if not target:
                raise DriverSourceError(f"#if {expr}: defined without a name")
            python.append("1" if target.group(1) in defines else "0")
            position += target.end()
        elif name:
            value = defines.get(name, "0").strip() or "1"
            if depth > 8:
                raise DriverSourceError(f"#if {expr}: {name} does not resolve")
            python.append(str(_condition_value(value, defines, depth + 1)))
        else:
            python.append(
                {"&&": " and ", "||": " or ", "!": " not ", "/": "//"}.get(operator, operator)
            )
    try:
        return int(_arithmetic(ast.parse("".join(python).strip(), mode="eval").body))
    except (SyntaxError, ZeroDivisionError, TypeError) as exc:
        raise DriverSourceError(f"#if {expr}: {exc}") from exc


_BINARY = {
    ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b, ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b, ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b, ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b, ast.BitXor: lambda a, b: a ^ b,
}
_COMPARE = {
    ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b, ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
}


def _arithmetic(node: ast.AST) -> int:
    """Integer arithmetic of an ``#if``, nothing else evaluated."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp):
        value = _arithmetic(node.operand)
        if isinstance(node.op, ast.Not):
            return int(not value)
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return value
        if isinstance(node.op, ast.Invert):
            return ~value
    if isinstance(node, ast.BoolOp):
        values = [_arithmetic(v) for v in node.values]
        return int(all(values) if isinstance(node.op, ast.And) else any(values))
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        return _BINARY[type(node.op)](_arithmetic(node.left), _arithmetic(node.right))
    if isinstance(node, ast.Compare):
        left = _arithmetic(node.left)
        for op, right_node in zip(node.ops, node.comparators):
            right = _arithmetic(right_node)
            if type(op) not in _COMPARE or not _COMPARE[type(op)](left, right):
                return 0
            left = right
        return 1
    raise TypeError(f"{type(node).__name__} in a condition")


class _Preprocessor:
    """Conditional compilation over src/, enough to tell which GAME and
    ROM_START a build compiles. Headers are read for their definitions."""

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers
        self._by_basename: dict[str, list[str]] = {}
        for path in headers:
            self._by_basename.setdefault(path.rsplit("/", 1)[-1], []).append(path)

    def _resolve(self, name: str, including: str) -> str | None:
        folder = including.rsplit("/", 1)[0]
        for candidate in (f"{folder}/{name}", f"src/{name}", f"src/includes/{name}"):
            if candidate in self.headers:
                return candidate
        found = self._by_basename.get(name.rsplit("/", 1)[-1], [])
        return found[0] if len(found) == 1 else None

    def run(
        self, path: str, text: str, defines: dict[str, str],
        local: dict[str, tuple[list[str] | None, str]] | None, seen: set[str],
    ) -> str:
        text = blank_comments(text, keep_lines=False).replace("\\\r\n", " ").replace("\\\n", " ")
        out: list[str] = []
        # Each level: (enclosing level active, a branch already taken, this branch active).
        stack: list[tuple[bool, bool, bool]] = []
        active = True
        for line in text.splitlines():
            directive = _DIRECTIVE.match(line)
            if not directive:
                if active:
                    out.append(line)
                continue
            word, rest = directive.groups()
            if word in _CONDITIONALS:
                active = _branch(path, word, rest, defines, stack, active)
            elif active:
                self._define(path, word, rest, defines, local, seen)
        if stack:
            raise DriverSourceError(f"{path}: #if without #endif")
        return "\n".join(out)

    def _define(
        self, path: str, word: str, rest: str, defines: dict[str, str],
        local: dict[str, tuple[list[str] | None, str]] | None, seen: set[str],
    ) -> None:
        """#define, #undef and #include in an active region."""
        if word == "define":
            head = _MACRO_HEAD.match(rest)
            if head:
                defines[head.group(1)] = head.group(3)
                if local is not None:
                    params = head.group(2)
                    local[head.group(1)] = (
                        [a.strip() for a in params[1:-1].split(",")] if params else None,
                        head.group(3),
                    )
        elif word == "undef":
            defines.pop(rest.strip(), None)
        elif word == "include":
            target = _INCLUDE.match(rest)
            header = self._resolve(target.group(1), path) if target else None
            if header and header not in seen:
                seen.add(header)
                self.run(header, self.headers[header], defines, None, seen)


_CONDITIONALS = frozenset({"if", "ifdef", "ifndef", "elif", "else", "endif"})


def _branch(
    path: str, word: str, rest: str, defines: dict[str, str],
    stack: list[tuple[bool, bool, bool]], active: bool,
) -> bool:
    """Apply one conditional directive to *stack*. Returns the new active state."""
    if word in ("if", "ifdef", "ifndef"):
        if not active:
            stack.append((False, True, False))
            return active
        if word == "if":
            value = bool(_condition_value(rest, defines))
        else:
            value = (rest.split()[0] in defines) == (word == "ifdef")
        stack.append((True, value, value))
        return value
    if word in ("elif", "else"):
        if not stack:
            raise DriverSourceError(f"{path}: #{word} without #if")
        outer, taken, _ = stack[-1]
        value = (
            outer and not taken
            and (word == "else" or bool(_condition_value(rest, defines)))
        )
        stack[-1] = (outer, taken or value, value)
        return value
    if not stack:
        raise DriverSourceError(f"{path}: #endif without #if")
    stack.pop()
    return stack[-1][2] if stack else True


def _dumped(args: list[str]) -> bool:
    """A ROM_LOAD whose ROM was dumped: 0.78 writes ``NO_DUMP`` in the hash
    argument, 0.37 a zero CRC."""
    if any("NO_DUMP" in a for a in args):
        return False
    crc = args[3] if len(args) > 3 else ""
    return not re.fullmatch(r"0[xX]0+|0", crc.strip())


def _argument(values: dict[str, str], match: re.Match[str]) -> str:
    return values.get(match.group(0), match.group(0))


def _expand_declarations(text: str, local: dict[str, tuple[list[str] | None, str]]) -> str:
    """Calls of a file's own function-like macros that write a ROM_START or a
    GAME line, expanded (pgm.c builds every DoDonPachi II set through
    ``DDP2_SET(name, program, asic)``)."""
    writers = {
        name: (params, body)
        for name, (params, body) in local.items()
        if params is not None and (_ROM_START_HEAD.search(body) or _GAME_MACRO.search(body))
    }
    if not writers:
        return text
    call = re.compile(r"\b(" + "|".join(map(re.escape, writers)) + r")\s*\(")
    out: list[str] = []
    position = 0
    for match in call.finditer(text):
        if match.start() < position:
            continue
        params, body = writers[match.group(1)]
        args, end = call_span(text, match.end())
        if len(args) != len(params):
            raise DriverSourceError(f"{match.group(1)} called with {len(args)} arguments")
        values = dict(zip(params, args))
        out.append(text[position : match.start()])
        out.append(_IDENTIFIER.sub(functools.partial(_argument, values), body))
        position = end
    out.append(text[position:])
    return "".join(out)


def compiled_drivers(driver_c: str, preprocessor: _Preprocessor) -> list[str]:
    """The DRIVER() entries driver.c compiles into the driver list."""
    # driver.c is read twice by the build, the second time with
    # DRIVER_RECURSIVE defined: that pass is the list.
    text = preprocessor.run(
        "src/driver.c", driver_c, {"DRIVER_RECURSIVE": "", "DRIVER": ""}, None, set()
    )
    return [n for n in _DRIVER_ENTRY.findall(text) if n != "NAME"]


def _holds_roms(
    body: str, local: dict[str, tuple[list[str] | None, str]], known: dict[str, bool],
    seen: frozenset[str] = frozenset(),
) -> bool:
    for match in _ROM_LOAD.finditer(body):
        if _dumped(call_args(body, match.end())):
            return True
    # A ROM list shared through a macro of the same file (a BIOS
    # block every game of the board pulls in).
    for word in set(_IDENTIFIER.findall(body)) - seen:
        if word in local:
            if word not in known:
                known[word] = _holds_roms(local[word][1], local, known, seen | {word})
            if known[word]:
                return True
    return False


def _read_driver(
    path: str, source: str, preprocessor: _Preprocessor,
    declared: dict[str, tuple[str | None, bool]], roms: dict[str, tuple[bool, bool]],
) -> None:
    """The ROM_START blocks and GAME declarations of one driver file."""
    local: dict[str, tuple[list[str] | None, str]] = {}
    text = _expand_declarations(preprocessor.run(path, source, {}, local, set()), local)
    known: dict[str, bool] = {}
    for match in _ROM_START.finditer(text):
        body = match.group(2)
        roms.setdefault(
            match.group(1), (_holds_roms(body, local, known), bool(_DISK_IMAGE.search(body)))
        )
    for match in _GAME_MACRO.finditer(text):
        args = call_args(text, match.end())
        if len(args) < 9:
            raise DriverSourceError(f"{path}: {match.group(1)} with {len(args)} arguments")
        name, parent = args[1], args[2]
        if name in declared:
            raise DriverSourceError(f"{path}: {name} declared twice")
        declared[name] = (
            None if parent == "0" else parent,
            any("NOT_A_DRIVER" in a for a in args[3:]),
        )


def driver_source_sets(
    driver_c: str, drivers: dict[str, str], headers: dict[str, str]
) -> dict[str, SetEntry]:
    """Every compiled set and every set on its parent chain, from the source.

    *drivers* maps each path under src/drivers/ to its text and *headers*
    every header under src/. A set is declared by a GAME-family macro whose
    ROMs are ``ROM_START(name)``, and a set flagged ``NOT_A_DRIVER`` is a BIOS
    set, the flag the 0.37 and 0.78 info.c use to tell a resource from a game.
    """
    preprocessor = _Preprocessor(headers)
    declared: dict[str, tuple[str | None, bool]] = {}
    roms: dict[str, tuple[bool, bool]] = {}
    for path, source in sorted(drivers.items()):
        _read_driver(path, source, preprocessor, declared, roms)
    compiled = compiled_drivers(driver_c, preprocessor)
    undeclared = [n for n in compiled if n not in declared]
    if undeclared:
        raise DriverSourceError(f"driver.c lists undeclared sets: {', '.join(undeclared[:10])}")
    sets: dict[str, SetEntry] = {}
    pending = list(compiled)
    while pending:
        name = pending.pop()
        if name in sets or name not in declared:
            continue
        parent, bios = declared[name]
        has_roms, disks = roms.get(name, (False, False))
        sets[name] = SetEntry(
            name=name, romof=parent, isbios=bios, runnable=not bios,
            has_roms=has_roms, disks=disks,
        )
        if parent:
            pending.append(parent)
    return sets


def git_tree_sha(entries: dict[str, tuple[str, str]]) -> str:
    """The sha git gives a directory, from ``{path: (mode, blob sha)}`` of
    every file under it, paths relative to it."""
    children: dict[str, dict[str, tuple[str, str]]] = {}
    rows: list[tuple[str, str, str]] = []
    for path, (mode, sha) in entries.items():
        head, sep, tail = path.partition("/")
        if sep:
            children.setdefault(head, {})[tail] = (mode, sha)
        else:
            rows.append((head, mode, sha))
    rows += [(name, "40000", git_tree_sha(sub)) for name, sub in children.items()]
    # git orders a tree by name, a directory compared as if it ended in "/".
    rows.sort(key=lambda row: row[0].encode() + (b"/" if row[1] == "40000" else b""))
    body = b"".join(
        mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha)
        for name, mode, sha in rows
    )
    return hashlib.sha1(f"tree {len(body)}\0".encode() + body).hexdigest()


@dataclass
class DriverSource:
    """What the reader needs from src/ at one commit, and the tree sha of
    src/ computed from every file of it."""

    driver_c: str
    drivers: dict[str, str]
    headers: dict[str, str]
    tree: str


def read_driver_source(tarball: Path) -> DriverSource:
    """src/ of a GitHub tarball: the texts the reader needs, and the git
    tree sha of the whole directory."""
    import tarfile

    entries: dict[str, tuple[str, str]] = {}
    texts: dict[str, str] = {}
    with tarfile.open(tarball, "r:gz") as archive:
        for member in archive:
            parts = member.name.split("/", 1)
            if len(parts) < 2 or not parts[1].startswith("src/"):
                continue
            path = parts[1]
            if member.issym():
                entries[path[4:]] = ("120000", git_blob_sha(member.linkname.encode()))
            elif member.isfile():
                handle = archive.extractfile(member)
                data = handle.read() if handle else b""
                mode = "100755" if member.mode & 0o111 else "100644"
                entries[path[4:]] = (mode, git_blob_sha(data))
                if path == "src/driver.c" or path.endswith(".h") or (
                    path.startswith("src/drivers/") and path.endswith(".c")
                ):
                    texts[path] = data.decode("latin-1")
    if "src/driver.c" not in texts:
        raise FileNotFoundError(f"{tarball} has no src/driver.c")
    return DriverSource(
        driver_c=texts["src/driver.c"],
        drivers={p: t for p, t in texts.items() if p.startswith("src/drivers/") and p.endswith(".c")},
        headers={p: t for p, t in texts.items() if p.endswith(".h")},
        tree=git_tree_sha(entries),
    )


def fetch_driver_source(
    slug: str, commit: str, cache_dir: Path, offline: bool = False
) -> DriverSource:
    """src/ at a commit, its tree sha checked against the repository's own
    when online."""
    tarball = cache_dir / "src" / slug / f"{commit}.tar.gz"
    if offline:
        if not tarball.is_file():
            raise FileNotFoundError(f"{tarball} is not cached")
    else:
        download(f"https://codeload.github.com/{slug}/tar.gz/{commit}", tarball,
                 skip_existing=True)
    source = read_driver_source(tarball)
    if not offline:
        listing = api_json(f"https://api.github.com/repos/{slug}/git/trees/{commit}")
        listed = next(
            (
                item.get("sha")
                for item in (listing.get("tree", []) if isinstance(listing, dict) else [])
                if item.get("path") == "src"
            ),
            None,
        )
        if listed != source.tree:
            tarball.unlink()
            raise BlobMismatchError(f"{slug}@{commit[:8]}:src is tree {listed}, not {source.tree}")
    return source
