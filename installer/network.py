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
from typing import Any, NoReturn

from installer.events import EVENTS
from installer.host_fs import _is_file, read_local_json
from installer.manifest import _check_standalone_layouts, _validate_manifest, _validate_targets
from installer.offline import LOCAL, _Offline, _network_allowed, offline_named, offline_undo, offline_words
from installer.platforms import TARGET_PLATFORMS, display_name
from installer.remote import (
    CONNECT_TIMEOUT,
    DEFAULT_RELEASE_REF,
    MANIFEST_URL,
    MAX_MANIFEST_BYTES,
    MAX_RETRIES,
    MAX_STANDALONE_BYTES,
    MAX_TARGETS_BYTES,
    RELEASE_REF,
    STANDALONE_DIR,
    STANDALONE_URL,
    TARGETS_URL,
    TROUBLESHOOTING_PAGE,
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


NETWORK_ADVICE = ("  Check the connection, and HTTPS_PROXY if this network needs a "
                  "proxy, then run the same command again.\n"
                  f"  More help: {TROUBLESHOOTING_PAGE}")


def read_local_manifest(path: Path, plat: str) -> dict:
    """A file list saved on disk, checked as a downloaded one is."""
    try:
        return _validate_manifest(read_local_json(path, MAX_MANIFEST_BYTES), plat)
    except OSError as exc:
        print(f"  Cannot read the file list {path}: {exc.strerror or exc}.", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        EVENTS.emit("error", stage="manifest", reason="invalid", platform=plat,
                    message=f"the file list is not valid: {exc}")
        print(f"  The file list {path} is not valid for {plat}: {exc}", file=sys.stderr)
        sys.exit(1)


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


def _address_lines(url: str) -> list[str]:
    """The address that failed, and the override that chose it if one did.

    A RETROBIOS_BASE_URL left from a mirror that is down read as a network
    fault: neither the host nor the variable was named.
    """
    lines = [f"  Address: {url}"]
    if os.environ.get("RETROBIOS_BASE_URL"):
        lines.append("  RETROBIOS_BASE_URL is set in this environment and chose that "
                     "address: unset it to read from the project itself.")
    return lines


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


def _manifest_invalid(plat: str, url: str, exc: ValueError) -> NoReturn:
    """Stop on a file list that arrived and is not valid."""
    words = f"the file list is not valid: {exc}"
    if isinstance(exc.__cause__, (json.JSONDecodeError, UnicodeDecodeError)):
        # The parser's "Expecting value: line 1 column 1" told no one
        # anything, where the full screen names the usual cause.
        words = ("what arrived is not a file list: a Wi-Fi sign-in page or a cut "
                 "download looks like this")
    EVENTS.emit("error", stage="manifest", reason="invalid", platform=plat,
                message=words)
    print(f"  For {display_name(plat)}, {words}.", file=sys.stderr)
    if words.startswith("what arrived"):
        for line in _address_lines(url):
            print(line, file=sys.stderr)
        print("  Check the connection (sign in to the Wi-Fi if it asks), then run the "
              "same command again.", file=sys.stderr)
    sys.exit(1)


def missing_list_advice(plat: str, again: str) -> str:
    """What to do when the revision asked for has no file list for plat:
    the name was checked before any request, so the revision is the cause."""
    if RELEASE_REF != DEFAULT_RELEASE_REF:
        return (f"RETROBIOS_REF={RELEASE_REF} has no list for {plat}: unset it, or pick a "
                "newer tag from https://github.com/Abdess/retrobios/releases.")
    return f"The repository may be moving its files: {again} in a few minutes."


def _manifest_http_error(plat: str, url: str, exc: urllib.error.HTTPError) -> NoReturn:
    """Stop on a file list the server answered with an HTTP error."""
    EVENTS.emit(
        "error", stage="manifest", reason="not_found" if exc.code == 404 else "network",
        platform=plat, message=f"the file list could not be fetched: HTTP {exc.code}",
    )
    if exc.code == 404 and os.environ.get("RETROBIOS_BASE_URL"):
        print(f"  No file list for {plat} there.", file=sys.stderr)
        for line in _address_lines(url):
            print(line, file=sys.stderr)
        sys.exit(1)
    if exc.code == 404:
        # Asked once, a 4xx being final. The name was checked before any
        # request, so the revision is what has no such list.
        print(f"  No file list for {plat} at {RELEASE_REF}.", file=sys.stderr)
        print(f"  {missing_list_advice(plat, 'run the same command again')}",
              file=sys.stderr)
        sys.exit(1)
    print(f"  Could not fetch the file list for {plat}: HTTP {exc.code}", file=sys.stderr)
    for line in _address_lines(url):
        print(line, file=sys.stderr)
    print(NETWORK_ADVICE, file=sys.stderr)
    sys.exit(1)


def _manifest_unreachable(plat: str, url: str, exc: OSError) -> NoReturn:
    """Stop on a file list the network did not bring."""
    code, words = network_words(exc)
    EVENTS.emit("error", stage="manifest", reason=code, platform=plat,
                message=words if code != "network"
                else f"the file list could not be fetched: {words}")
    if code == "offline":
        print(f"  No file list for {plat}: {offline_words()}. Give --manifest FILE "
              f"(a copy of install/{plat}.json) or --from-pack PACK, or run "
              f"{offline_undo()}.", file=sys.stderr)
        sys.exit(1)
    if code != "network":
        print(f"  Could not fetch the file list for {plat}.", file=sys.stderr)
        print(f"  {words}.", file=sys.stderr)
        sys.exit(1)
    tries = getattr(exc, "attempts", MAX_RETRIES)
    print(f"  Could not fetch the file list for {plat} after {tries} "
          f"attempts: {words}", file=sys.stderr)
    for line in _address_lines(url):
        print(line, file=sys.stderr)
    print(NETWORK_ADVICE, file=sys.stderr)
    sys.exit(1)


def fetch_manifest(plat: str) -> dict:
    """Download platform manifest JSON, or read the one this run was given."""
    if LOCAL.manifest is not None:
        return read_local_manifest(LOCAL.manifest, plat)
    if LOCAL.pack is not None:
        try:
            return _validate_manifest(LOCAL.pack.manifest(plat), plat)
        except ValueError as exc:
            print(f"  The file list in {LOCAL.pack.name} is not valid: {exc}",
                  file=sys.stderr)
            sys.exit(1)
    url = MANIFEST_URL.format(platform=plat)
    try:
        return _validate_manifest(_fetch_json(url, MAX_MANIFEST_BYTES, "file list"), plat)
    except ValueError as exc:
        _manifest_invalid(plat, url, exc)
    except urllib.error.HTTPError as exc:
        _manifest_http_error(plat, url, exc)
    except (urllib.error.URLError, OSError) as exc:
        _manifest_unreachable(plat, url, exc)


def _pack_alone(plat: str) -> bool:
    """A pack read without a file list for plat: one built before packs
    carried their install list records the systems of its files only."""
    return (LOCAL.pack is not None and LOCAL.manifest is None
            and (LOCAL.pack.install_list or {}).get("platform") != plat)


def local_targets(plat: str) -> "dict | None":
    """The cores per board this run has without the network: the list the
    pack carries, else targets/<platform>.json beside --manifest, where the
    repository keeps it (install/targets/). None when there is neither."""
    if LOCAL.pack is not None and LOCAL.pack.targets is not None \
            and plat in LOCAL.pack.platforms():
        return LOCAL.pack.targets
    if LOCAL.manifest is None:
        return None
    beside = LOCAL.manifest.parent / "targets" / f"{plat}.json"
    if not _is_file(beside):
        return None
    try:
        return _validate_targets(read_local_json(beside, MAX_TARGETS_BYTES))
    except OSError as exc:
        # Read as absent, the offline run asked for the file already there.
        print(f"  Error: the target list {beside} cannot be read: {exc.strerror or exc}",
              file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"  Error: the target list {beside} is not valid: {exc}", file=sys.stderr)
        sys.exit(1)


def fetch_standalone(plat: str, manifest: dict) -> dict:
    """What each standalone build reads, for --standalone only: the file
    beside --manifest (standalone/<platform>.json, where the repository
    keeps it), else downloaded as the list is. Missing, unreachable or
    invalid, the run stops on one line, code 1."""
    beside = (LOCAL.manifest.parent / STANDALONE_DIR / f"{plat}.json"
              if LOCAL.manifest is not None else None)
    url = STANDALONE_URL.format(platform=plat)
    where = str(beside) if beside is not None and _is_file(beside) else url
    try:
        if where != url:
            data = read_local_json(Path(where), MAX_STANDALONE_BYTES)
        else:
            data = _fetch_json(url, MAX_STANDALONE_BYTES, "standalone layout")
        return _check_standalone_layouts(data, manifest, plat)
    except urllib.error.HTTPError as exc:
        problem = f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError) as exc:
        problem = (str(exc) if isinstance(exc, _Offline)
                   else exc.strerror or str(exc) if where != url
                   else network_words(exc)[1])
    except ValueError as exc:
        problem = f"not valid: {exc}"
    EVENTS.emit("error", stage="manifest", reason="unavailable", platform=plat,
                message=f"--standalone needs {where}: {problem}")
    print(f"Error: --standalone needs {where}, which could not be read ({problem}).",
          file=sys.stderr)
    sys.exit(1)


def fetch_targets(plat: str, attempts: int = MAX_RETRIES,
                  timeout: float | None = None) -> "dict | None":
    """The target core list: the one this run has at hand, else downloaded.

    Empty on 404, where the platform publishes no targets. None when the list
    could not be read: a timeout says nothing about the platform, and
    answering "no targets" for it sent users to the full pack. A run without
    the network and with no list at hand is refused, code 2, before any
    file is written.
    """
    held = local_targets(plat)
    if held is not None:
        return held
    if LOCAL.offline and plat not in TARGET_PLATFORMS:
        return {}
    if LOCAL.offline:
        source = (f"{LOCAL.pack.name} carries none" if LOCAL.pack is not None
                  else f"{offline_named()} makes no request")
        print(f"Error: --target needs the {display_name(plat)} board list ({source}). Put "
              f"install/targets/{plat}.json beside the --manifest file, or go online.",
              file=sys.stderr)
        sys.exit(2)
    url = TARGETS_URL.format(platform=plat)
    try:
        return _validate_targets(_fetch_json(url, MAX_TARGETS_BYTES, "target list",
                                             attempts=attempts, timeout=timeout))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        print(f"  Error: failed to fetch targets for {plat}: {exc}", file=sys.stderr)
        for line in _address_lines(url):
            print(line, file=sys.stderr)
        print(NETWORK_ADVICE, file=sys.stderr)
        return None
    except ValueError as exc:
        print(f"  Error: the target list for {plat} is not valid: {exc}", file=sys.stderr)
        return None
    except (urllib.error.URLError, OSError) as exc:
        print(f"  Error: failed to fetch targets for {plat}: "
              f"{network_words(exc)[1]}", file=sys.stderr)
        for line in _address_lines(url):
            print(line, file=sys.stderr)
        print(NETWORK_ADVICE, file=sys.stderr)
        return None


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
