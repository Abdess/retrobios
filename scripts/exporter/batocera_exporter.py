"""Exporter for Batocera's batocera-systems.

batocera-systems is an executable script: the systems dict is one block
inside it, the rest is the checker Batocera runs. Only the block is
rewritten, entry by entry, so the comments the maintainers wrote between
entries and the code around them survive untouched.
"""

from __future__ import annotations

import re

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/batocera-linux/batocera.linux/master"
    "/package/batocera/core/batocera-scripts/scripts/batocera-systems"
)

_ENTRY_START = re.compile(r'^(\s{4})"([^"]+)":\s*\{')
_INDENT = " " * 4


class Exporter(BaseExporter):
    """Write Batocera's batocera-systems, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "batocera"

    @staticmethod
    def native_filename() -> str:
        return "batocera-systems"

    @staticmethod
    def requires() -> str:
        return "md5"

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"md5"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"batocera-systems": SOURCE_URL}

    @staticmethod
    def needs_original() -> bool:
        # The data block is a fraction of the file; the rest is the checker.
        return True

    def _bios_files(self, files: list[NativeFile]) -> str:
        return ", ".join(self._bios_items(files))

    def _bios_items(self, files: list[NativeFile]) -> list[str]:
        parts: list[str] = []
        for fe in files:
            # The platform states an unhashed file as an empty md5 rather
            # than leaving it out, and so do we.
            item = [f'"md5": "{fe.hash("md5")}"']
            alt = fe.native("alt_md5", "")
            if alt:
                item.append(f'"altmd5": "{alt}"')
            declared = fe.native("native_path", "")
            path = str(declared) if declared else f"bios/{fe.destination}"
            item.append(f'"file": "{path}"')
            zipped = fe.native("zipped_file", "")
            if zipped:
                item.append(f'"zippedFile": "{zipped}"')
            parts.append("{ " + ", ".join(item) + " }")
        return parts

    def _entry_line(self, system: NativeSystem, files: list[NativeFile]) -> str:
        return (
            f'{_INDENT}"{system.native_id}": '
            f'{{ "name": "{self.display_name(system)}", '
            f'"biosFiles": [ {self._bios_files(files)} ] }},'
        )

    @staticmethod
    def _item_notes(lines: list[str]) -> tuple[dict[str, str], dict[str, list[str]]]:
        """The notes a maintainer wrote about each file, keyed by its path.

        Rewriting an entry as one line would drop them, and a note like
        "ideally - 94bc50..." is the only record of why a hash is blank.
        A comment on its own line belongs to the file below it; a comment at
        the end of a line belongs to the file on it.
        """
        trailing: dict[str, str] = {}
        leading: dict[str, list[str]] = {}
        pending: list[str] = []
        for line in lines:
            stripped = line.strip()
            hash_at = line.find("#")
            if stripped.startswith("#"):
                pending.append(stripped)
                continue
            path = re.search(r'"file"\s*:\s*"([^"]+)"', line)
            if not path:
                continue
            key = path.group(1)
            if pending:
                leading[key] = pending
                pending = []
            if 0 <= hash_at and hash_at > line.index(key):
                trailing[key] = line[hash_at:].rstrip()
        return trailing, leading

    def _entry_block(
        self,
        system: NativeSystem,
        files: list[NativeFile],
        original: list[str],
    ) -> list[str]:
        """One entry, keeping the layout and the notes it was written with."""
        trailing, leading = self._item_notes(original)
        items = self._bios_items(files)
        one_line = len(original) == 1 and not trailing and not leading
        if one_line:
            return [self._entry_line(system, files)]

        head = (
            f'{_INDENT}"{system.native_id}": '
            f'{{ "name": "{self.display_name(system)}", "biosFiles": ['
        )
        pad = " " * (len(_INDENT) + 4)
        lines = [head]
        for index, item in enumerate(items):
            key = self._item_path(item)
            lines.extend(f"{pad}{note}" for note in leading.get(key, []))
            separator = "," if index < len(items) - 1 else ""
            note = trailing.get(key, "")
            suffix = f" {note}" if note else ""
            lines.append(f"{pad}{item}{separator}{suffix}")
        lines.append(f"{_INDENT}] }},")
        return lines

    @staticmethod
    def _item_path(item: str) -> str:
        match = re.search(r'"file": "([^"]+)"', item)
        return match.group(1) if match else ""

    @staticmethod
    def _split_original(original: str) -> tuple[list[str], list[str], list[str]]:
        """Cut the script into what precedes the dict, the dict, what follows."""
        lines = original.split("\n")
        start = next(
            (i for i, line in enumerate(lines) if line.startswith("systems = {")),
            None,
        )
        if start is None:
            raise ValueError("batocera-systems: no systems dict found")
        end = next(
            (i for i in range(start + 1, len(lines)) if lines[i].startswith("}")),
            None,
        )
        if end is None:
            raise ValueError("batocera-systems: the systems dict is not closed")
        return lines[: start + 1], lines[start + 1 : end], lines[end:]

    @staticmethod
    def _entry_spans(body: list[str]) -> dict[str, tuple[int, int]]:
        """Locate each top-level entry, which may wrap over several lines."""
        spans: dict[str, tuple[int, int]] = {}
        index = 0
        while index < len(body):
            match = _ENTRY_START.match(body[index])
            if not match:
                index += 1
                continue
            key = match.group(2)
            depth = 0
            end = index
            for cursor in range(index, len(body)):
                depth += body[cursor].count("{") + body[cursor].count("[")
                depth -= body[cursor].count("}") + body[cursor].count("]")
                if depth <= 0:
                    end = cursor
                    break
            else:
                end = len(body) - 1
            spans[key] = (index, end)
            index = end + 1
        return spans

    @staticmethod
    def _parse_entry(lines: list[str]) -> dict | None:
        """Evaluate one entry so two spellings of the same data compare equal."""
        text = "\n".join(lines).strip().rstrip(",")
        namespace: dict[str, object] = {}
        try:
            exec(f"entry = {{{text}}}", {}, namespace)  # noqa: S102
        except (SyntaxError, ValueError, TypeError):
            return None
        entry = namespace.get("entry")
        return entry if isinstance(entry, dict) else None

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        exportable = dict(
            (system.native_id, (system, files))
            for system, files in self.exportable(systems, require="md5")
        )

        original = originals.get(self.native_filename(), "")
        if not original:
            raise ValueError(
                f"{self.native_filename()} cannot be written without the "
                "platform's own file: the systems dict is a fraction of a "
                "script, and the rest of it is the checker"
            )

        head, body, tail = self._split_original(original)
        spans = self._entry_spans(body)

        rebuilt: list[str] = []
        written: set[str] = set()
        index = 0
        for key, (start, end) in sorted(spans.items(), key=lambda kv: kv[1][0]):
            rebuilt.extend(body[index:start])
            pair = exportable.get(key)
            index = end + 1
            if pair is None:
                # The truth has nothing to say and no file left to declare.
                rebuilt.extend(body[start:end + 1])
                continue
            written.add(key)
            original_lines = body[start:end + 1]
            replacement = self._entry_line(*pair)
            before = self._parse_entry(original_lines)
            after = self._parse_entry([replacement])
            if before is not None and before == after:
                # Nothing changed: keep the maintainer's own lines, comments
                # and alignment included, so the diff shows only corrections.
                rebuilt.extend(original_lines)
            else:
                rebuilt.extend(self._entry_block(*pair, original_lines))
        rebuilt.extend(body[index:])

        added = [
            self._entry_line(system, files)
            for native_id, (system, files) in exportable.items()
            if native_id not in written
        ]
        if added:
            while rebuilt and not rebuilt[-1].strip():
                rebuilt.pop()
            rebuilt.append("")
            rebuilt.extend(sorted(added))
            rebuilt.append("")

        return {self.native_filename(): "\n".join([*head, *rebuilt, *tail])}

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        content = produced[self.native_filename()]
        issues: list[str] = []

        namespace: dict[str, object] = {}
        block = content.split("\nsystems = {", 1)
        if len(block) != 2:
            return ["no systems dict in the output"]
        end = block[1].find("\n}")
        if end < 0:
            return ["the systems dict is not closed"]
        try:
            exec("systems = {" + block[1][:end] + "\n}", {}, namespace)  # noqa: S102
        except SyntaxError as exc:
            return [f"the systems dict does not parse: {exc}"]

        exported = namespace.get("systems", {})
        if not isinstance(exported, dict):
            return ["the systems dict did not evaluate to a dict"]

        for system, files in self.exportable(systems, require="md5"):
            entry = exported.get(system.native_id)
            if entry is None:
                issues.append(f"system absent: {system.native_id}")
                continue
            declared = {bios.get("file", "") for bios in entry.get("biosFiles", [])}
            for fe in files:
                path = str(fe.native("native_path", "")) or f"bios/{fe.destination}"
                if path not in declared:
                    issues.append(f"absent: {system.native_id}/{fe.name}")

        for native_id, entry in exported.items():
            if not entry.get("biosFiles"):
                issues.append(f"empty entry: {native_id}")

        if "def checkBios(" not in content:
            issues.append("the checker the script exists for is missing")
        return issues
