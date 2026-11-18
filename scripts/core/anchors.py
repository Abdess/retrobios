"""Heading ids as the site's Markdown renderer spells them."""

from __future__ import annotations

import re
import unicodedata
from html import unescape


IDCOUNT = re.compile(r"^(.*)_([0-9]+)$")


# Heading ids, as Python-Markdown's toc extension gives them


def toc_slug(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = unescape(text.replace("`", "").replace("**", "").replace("\\", ""))
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", text)


def _unique(ident: str, used: set[str]) -> str:
    while ident in used or not ident:
        match = IDCOUNT.match(ident)
        ident = f"{match[1]}_{int(match[2]) + 1}" if match else f"{ident}_1"
    used.add(ident)
    return ident
