"""The guard a test module turns on for itself and the Python it starts
(sitecustomize). module_guard() gives the setUpModule and tearDownModule
pair: the module fails at its end when anything tried to leave the loopback."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from .sitecustomize import disable, enable, refused

__all__ = ["module_guard", "enable", "disable", "refused"]


def module_guard(name: str) -> tuple[Callable[[], None], Callable[[], None]]:
    log = Path(__file__).resolve().parents[2] / "tmp" / "tests" / f"netlog-{name}-{os.getpid()}"
    state: dict = {}

    def set_up() -> None:
        log.parent.mkdir(parents=True, exist_ok=True)
        state["before"] = enable(str(log))

    def tear_down() -> None:
        disable(state.pop("before", {}))
        tried = refused(str(log))
        log.unlink(missing_ok=True)
        if tried:
            raise AssertionError(
                f"{len(tried)} connections off the loopback during {name} (pid host): "
                + ", ".join(tried[:10]))

    return set_up, tear_down
