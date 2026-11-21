"""TLS, connections, and the file lists downloaded or read from disk."""
from __future__ import annotations

import datetime
import errno
import http.client
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from installer.offline import _Offline, _network_allowed
from installer.remote import (
    CONNECT_TIMEOUT,
    MAX_RETRIES,
)


def _read_limited(response: http.client.HTTPResponse, limit: int, label: str) -> bytes:
    """Read a response of limit bytes at most.

    A body shorter than its Content-Length is a dropped connection, raised
    as one so the caller retries: parsed, the cut read as an invalid file
    list and the run ended without the network advice.
    """
    raw_length = response.headers.get("Content-Length") if response.headers else None
    expected: int | None = None
    if raw_length:
        try:
            expected = int(raw_length)
        except ValueError:
            expected = None
        if expected is not None and expected > limit:
            raise ValueError(f"{label} exceeds {limit} bytes")
    try:
        payload = response.read(limit + 1)
    except http.client.IncompleteRead as exc:
        raise ConnectionError(
            f"{label} cut after {len(exc.partial)} bytes"
        ) from exc
    if len(payload) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    if expected is not None and len(payload) < expected:
        raise ConnectionError(f"{label} cut after {len(payload)} of {expected} bytes")
    return payload


def _read_limited_json(
    response: http.client.HTTPResponse, limit: int, label: str, raw: bool = False
) -> object:
    """Read a bounded UTF-8 JSON response, its bytes as they came with raw."""
    payload = _read_limited(response, limit, label)
    if raw:
        return payload
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc


# The installer was written after this day. A clock that reads earlier is
# wrong, and TLS then finds every certificate not yet valid: a handheld
# with no clock battery boots on 1970 or 1980.
CLOCK_FLOOR = datetime.date(2026, 1, 1)
# Where systems keep their trusted certificates, for a Python built to look
# elsewhere: Debian, Fedora, openSUSE, the BSDs and macOS, Homebrew, Termux.
CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/ssl/cert.pem",
    "/usr/local/etc/openssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem",
    "/data/data/com.termux/files/usr/etc/tls/cert.pem",
)
# Set from --verbose: the error text Python gives stays beside the words.
_RAW_ERRORS = threading.Event()


def _default_ca_present() -> bool:
    """Whether the certificates this Python reads by default exist."""
    import ssl

    paths = ssl.get_default_verify_paths()
    for value in (os.environ.get("SSL_CERT_FILE"), paths.cafile, paths.openssl_cafile):
        if value and Path(value).is_file():
            return True
    for value in (os.environ.get("SSL_CERT_DIR"), paths.capath, paths.openssl_capath):
        try:
            if value and any(Path(value).iterdir()):
                return True
        except OSError:
            continue
    return False


def _known_bundle() -> str:
    """A certificate bundle the system keeps where this Python does not look."""
    return next((path for path in CA_BUNDLES if Path(path).is_file()), "")


def _ca_bundle_found() -> bool:
    """Whether any list of trusted certificates is on this machine.

    Windows verifies against its own store, which Python reads directly.
    """
    return os.name == "nt" or _default_ca_present() or bool(_known_bundle())


def network_words(
    exc: BaseException, today: datetime.date | None = None, verbose: bool | None = None,
) -> tuple[str, str]:
    """The reason a request failed, and the same in words a beginner reads.

    The reason is clock, no_ca, no_ssl, network, or offline for a request the run
    was told not to make. Offline, the run printed
    "[Errno -2] Name or service not known": the raw text now follows the
    words only under --verbose.
    """
    if isinstance(exc, _Offline):
        return "offline", str(exc)
    reason = getattr(exc, "reason", None)
    inner = reason if isinstance(reason, BaseException) else exc
    raw = str(reason or exc)
    code, words = "network", ""
    cert_error = getattr(sys.modules.get("ssl"), "SSLCertVerificationError", None)
    if (isinstance(exc, urllib.error.URLError) and raw.startswith("unknown url type")
            and not hasattr(urllib.request, "HTTPSHandler")):
        # urllib defines no HTTPS handler in a Python built without ssl:
        # three attempts and a word on the connection blamed the network.
        code = "no_ssl"
        words = ("This Python was built without its ssl module and cannot use HTTPS. "
                 "Run the installer with another Python 3.8 or newer")
    elif cert_error is not None and isinstance(inner, cert_error):
        today = today or datetime.date.today()
        if not _ca_bundle_found():
            code = "no_ca"
            words = ("This system has no list of trusted certificates to check the "
                     "server with. Install the ca-certificates package, or name a "
                     "certificate bundle with SSL_CERT_FILE, then run again")
        elif today < CLOCK_FLOOR:
            code = "clock"
            words = (f"The clock reads {today.isoformat()}: connect to Wi-Fi and let the "
                     "time sync, or set the date, then run again")
        else:
            words = "the server's certificate was rejected"
            bundle = "" if _default_ca_present() else _known_bundle()
            words += (f": this Python reads no certificate list, run again with "
                      f"SSL_CERT_FILE={bundle}" if bundle
                      else ", which a proxy or a filter on this network can cause")
    elif isinstance(inner, socket.gaierror):
        words = "no internet connection, or the server name could not be looked up"
    elif isinstance(inner, (socket.timeout, TimeoutError)):
        words = "the connection timed out"
    elif isinstance(inner, ConnectionRefusedError):
        words = "the server refused the connection"
    elif isinstance(inner, OSError) and inner.errno in (
            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN):
        words = "no internet connection: the network cannot be reached"
    elif isinstance(inner, (ConnectionResetError, ConnectionAbortedError,
                            http.client.HTTPException)):
        words = "the connection was cut"
    if not words:
        return code, raw
    if _RAW_ERRORS.is_set() if verbose is None else verbose:
        words += f" [{raw}]"
    return code, words


OVERRIDE_LINE = ("  RETROBIOS_BASE_URL is set in this environment and chose that "
                 "address: unset it to read from the project itself.")


def _address_lines(url: str, overridden: bool) -> list[str]:
    """The address that failed, and the override that chose it if one did.

    A RETROBIOS_BASE_URL left from a mirror that is down read as a network
    fault: neither the host nor the variable was named.
    """
    return [f"  Address: {url}", *([OVERRIDE_LINE] if overridden else [])]


def _open_socket(
    address: tuple[str, int], timeout: object, source_address: tuple[str, int] | None = None,
) -> socket.socket:
    """A connection given CONNECT_TIMEOUT to open, then the caller's timeout."""
    limit = min(CONNECT_TIMEOUT, timeout) if isinstance(timeout, (int, float)) else CONNECT_TIMEOUT
    sock = socket.create_connection(address, limit, source_address)
    sock.settimeout(timeout if isinstance(timeout, (int, float)) else socket.getdefaulttimeout())
    return sock


class _BoundedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _open_socket


class _BoundedHTTPHandler(urllib.request.HTTPHandler):
    def do_open(self, http_class: Any, req: Any, **kwargs: Any) -> Any:
        return super().do_open(_BoundedHTTPConnection, req, **kwargs)


def install_bounded_opener() -> None:
    """Every request of the run opens its connection in CONNECT_TIMEOUT.

    The proxy variables are read as before: build_opener keeps its
    ProxyHandler, and only the HTTP and HTTPS handlers are replaced.
    """
    handlers: list[type] = [_BoundedHTTPHandler]
    if hasattr(http.client, "HTTPSConnection"):
        class _BoundedHTTPSConnection(http.client.HTTPSConnection):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                self._create_connection = _open_socket

        class _BoundedHTTPSHandler(urllib.request.HTTPSHandler):
            def do_open(self, http_class: Any, req: Any, **kwargs: Any) -> Any:
                return super().do_open(_BoundedHTTPSConnection, req, **kwargs)

        handlers.append(_BoundedHTTPSHandler)
    urllib.request.install_opener(urllib.request.build_opener(*handlers))


# The wait for each answer of a file list, its first byte included: a
# server that takes the connection and never answers (a captive portal, a
# stuck proxy) held the run 93 s on three waits of 30 s. A list is a few
# MB, never a slow stream.
LIST_TIMEOUT = 15.0
# Attempts after a wait ran out, for the connection (a TLS handshake a
# captive portal never finishes) or for the answer once connected (a stuck
# proxy): once more, a stall is rarely a blip.
STALLED_ATTEMPTS = 2


def _stalled(exc: BaseException) -> bool:
    """Whether exc is a wait that ran out: urllib raises a connect timeout
    as a URLError whose reason is the timeout, a silent answer as the
    timeout itself."""
    reason = getattr(exc, "reason", None)
    return isinstance(exc, socket.timeout) or isinstance(reason, socket.timeout)


def _fetch_json(
    url: str, limit: int, label: str, attempts: int = MAX_RETRIES,
    timeout: float | None = None, raw: bool = False,
) -> Any:
    """A JSON document, tried MAX_RETRIES times like every file download.
    raw gives its bytes, for a document checked against a digest.

    A file list fetched once ended the run on one timeout over flaky Wi-Fi.
    A 4xx answer or an invalid document is final: asking again changes
    nothing, and a server gone silent is asked once more only.
    """
    _network_allowed(label)
    timeout = LIST_TIMEOUT if timeout is None else timeout
    for attempt in range(1, attempts + 1):
        # The tries this failure gets: "(2/3)" then "after 2 attempts" for
        # a server gone silent, asked once more only.
        tries = attempts
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                if raw:
                    return _read_limited_json(resp, limit, label, raw=True)
                return _read_limited_json(resp, limit, label)
        except urllib.error.HTTPError as exc:
            wait = _retry_after_failure(exc, attempt, attempts)
            if wait is None:
                raise
            delay = wait
            problem = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            problem = network_words(exc)[1]
            wait = _retry_after_failure(exc, attempt, attempts)
            if wait is None or (_stalled(exc) and attempt >= STALLED_ATTEMPTS):
                if isinstance(exc, http.client.HTTPException):
                    raise ConnectionError(f"connection cut: {exc!r}") from exc
                # How many were made, for the line that says so.
                exc.__dict__["attempts"] = attempt
                raise
            delay = wait
            if _stalled(exc):
                tries = min(attempts, STALLED_ATTEMPTS)
        # Said, or three 30-second attempts read as a frozen program.
        print(f"  The {label} did not arrive ({problem}), trying again "
              f"({attempt + 1}/{tries}) in {delay:.0f} s.", file=sys.stderr)
        time.sleep(delay)
    raise AssertionError("unreachable")


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    """Seconds before the next attempt: what the server asks, else 1, 2, 4."""
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), 60.0)
        except ValueError:
            pass
    return float(min(2 ** (attempt - 1), 8))


def _server_delay(exc: urllib.error.HTTPError, attempt: int) -> float:
    """Seconds before asking a server that refused again: its Retry-After."""
    return _retry_delay(attempt, exc.headers.get("Retry-After") if exc.headers else None)


def _retry_after_failure(exc: BaseException, attempt: int, attempts: int) -> float | None:
    """Seconds before the attempt after exc, None when it is final: the last
    attempt, a refusal other than 429, a wrong clock or no certificate list,
    which fail every attempt alike."""
    if attempt >= attempts:
        return None
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code < 500 and exc.code != 429:
            return None
        return _server_delay(exc, attempt)
    if network_words(exc)[0] != "network":
        return None
    return _retry_delay(attempt, None)


def _read_capped(path: Path, limit: int) -> bytes | None:
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None
