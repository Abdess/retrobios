"""install.py read as a module, once per run."""

from __future__ import annotations

import functools
import importlib.util
import types

from core.paths import REPO_ROOT


@functools.cache
def installer_module() -> types.ModuleType:
    """The generated install.py, the artifact served, for its constants and
    words: the schema, the doc tables, the launcher index and the site read
    the same module."""
    path = REPO_ROOT / "install.py"
    spec = importlib.util.spec_from_file_location("install", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
