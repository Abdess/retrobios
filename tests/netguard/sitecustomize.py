"""The machine running the installer tests, kept out of them.

Python imports this module at start in every process a test starts with
tests/netguard on PYTHONPATH (enable), and the test module
calls guard() for its own process. Two things the host has never reach a
test: a connection off the loopback, which is refused (OSError, as a network
that is down) and written to RETROBIOS_TEST_NETLOG, and the cards and drives
mounted under /media, /run/media, /mnt and /Volumes, which read as folders
no drive is mounted on. A test module passed on a machine with no network
and no card, and failed with an AmberELEC card in the reader, while 261
connections to GitHub left the module in a run (code_audit_24 P3-13).
"""

from __future__ import annotations

import errno
import os
import socket
import sys

LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0", ""})
MOUNT_ROOTS = ("/media", "/run/media", "/mnt", "/Volumes")
NETLOG = "RETROBIOS_TEST_NETLOG"
# What guard() replaced, for unguard().
_SAVED: dict = {}


def _refuse(host: object) -> None:
    where = os.environ.get(NETLOG)
    if where:
        with open(where, "a", encoding="utf-8") as log:
            log.write(f"{os.getpid()} {host} {' '.join(sys.argv)[:300]}\n")
    raise OSError(errno.ENETUNREACH, f"a test makes no request to {host}")


def guard() -> None:
    """Refuse every connection off the loopback, hide the host's mounts."""
    if _SAVED:
        return
    _SAVED.update(connect=socket.socket.__dict__.get("connect"),
                  connect_ex=socket.socket.__dict__.get("connect_ex"),
                  getaddrinfo=socket.getaddrinfo, ismount=os.path.ismount)
    connect = socket.socket.connect
    connect_ex = socket.socket.connect_ex
    getaddrinfo = socket.getaddrinfo

    def host_of(address: object) -> object:
        return address[0] if isinstance(address, tuple) and address else None

    def checked(sock: socket.socket, address: object) -> None:
        if sock.family in (socket.AF_INET, socket.AF_INET6) and \
                host_of(address) not in LOOPBACK:
            _refuse(host_of(address))

    def guarded_connect(self: socket.socket, address: object) -> None:
        checked(self, address)
        return connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: object) -> int:
        checked(self, address)
        return connect_ex(self, address)

    def guarded_getaddrinfo(host: object, *args: object, **kwargs: object) -> list:
        if host is not None and str(host) not in LOOPBACK:
            _refuse(host)
        return getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]

    ismount = os.path.ismount

    def guarded_ismount(path: object) -> bool:
        text = os.fspath(path) if not isinstance(path, str) else path
        if isinstance(text, bytes):
            text = text.decode(errors="replace")
        if any(text == root or text.startswith(root + "/") for root in MOUNT_ROOTS):
            return False
        return ismount(path)

    os.path.ismount = guarded_ismount  # type: ignore[assignment]


def unguard() -> None:
    """The process as it was before guard()."""
    if not _SAVED:
        return
    for name in ("connect", "connect_ex"):
        if _SAVED[name] is None:
            delattr(socket.socket, name)
        else:
            setattr(socket.socket, name, _SAVED[name])
    socket.getaddrinfo = _SAVED["getaddrinfo"]
    os.path.ismount = _SAVED["ismount"]
    _SAVED.clear()


def enable(log: str) -> dict:
    """Guard this process and every Python it starts, the refusals written
    to log. Returns the variables it changed, for disable()."""
    before = {name: os.environ.get(name) for name in ("PYTHONPATH", NETLOG)}
    here = os.path.dirname(os.path.abspath(__file__))
    paths = [here, *[p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p]]
    os.environ["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(paths))
    os.environ[NETLOG] = log
    with open(log, "w", encoding="utf-8"):
        pass
    guard()
    return before


def disable(before: dict) -> None:
    """This process and the Python it starts as before enable()."""
    unguard()
    for name, value in before.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def refused(log: str) -> list[str]:
    """The connections refused since enable(log), one line each."""
    try:
        with open(log, encoding="utf-8") as text:
            return [line.strip() for line in text if line.strip()]
    except OSError:
        return []


if os.environ.get(NETLOG):
    guard()
