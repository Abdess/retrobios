"""A folder served over loopback HTTP, for the installer tests."""

from __future__ import annotations

import functools
import hashlib
import http.server
import socket
import threading
import unittest
import zlib
from pathlib import Path
from typing import Callable


class Quiet(http.server.SimpleHTTPRequestHandler):
    """Serves files without a log line per request."""

    def log_message(self, format, *args):
        return


def serve(test: unittest.TestCase, directory: Path | None = None,
          handler: Callable[..., http.server.BaseHTTPRequestHandler] = Quiet) -> str:
    """The base URL of a server for the test's length, serving directory
    (or answering with handler alone when none is given)."""
    factory = functools.partial(handler, directory=str(directory)) if directory else handler
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), factory)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return f"http://127.0.0.1:{server.server_address[1]}"


def closed_port() -> int:
    """A loopback port nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def noise(seed: str, size: int) -> bytes:
    """Bytes deflate cannot shrink."""
    return b"".join(hashlib.sha256(f"{seed}{n}".encode()).digest()
                    for n in range(size // 32))


def crc(data: bytes) -> str:
    """The CRC-32 as the manifests write it."""
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
