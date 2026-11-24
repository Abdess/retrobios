"""HTTP to the forges: request headers, retries, quota waits, capped reads and the errors they raise."""

from __future__ import annotations

import http.client
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Mapping, Protocol, TypeVar

from core.artifacts import atomic_scratch
from core.offline import OFFLINE_ENV, run_is_offline

USER_AGENT = "retrobios-profile-sync/1.0"
# A body read whole into memory is capped at this many bytes.
MAX_RESPONSE_SIZE = 50 * 1024 * 1024
RETRIES = 3
RETRY_BACKOFF = (0.5, 2.0)
# A 429 is waited out, as base_scraper does: git.libretro.com answers it
# a few hundred requests into a pass and serves again a minute later.
RATE_LIMIT_WAITS = (5.0, 20.0, 60.0)
RATE_LIMIT_WAIT_CAP = 120.0
# The hosts the GitHub token is sent to. github.com is not one: a release
# download there redirects to asset storage, and urllib carries the header
# across the redirect.
TOKEN_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com"})


_T = TypeVar("_T")
_sleep = time.sleep
# Hosts still refusing after every wait. Asking them again in the same pass
# only spends the waits again, while the other forges keep answering.
_exhausted_hosts: set[str] = set()


class UpstreamError(Exception):
    """Any failure while talking to a forge."""


class RateLimitError(UpstreamError):
    """The forge refused the request for quota reasons."""

    def __init__(self, message: str, host: str = "") -> None:
        super().__init__(message)
        self.host = host


class NotCachedError(UpstreamError):
    """An offline read of something the cache never stored.

    Distinct from absence: returning None made profile_sync report a file
    that exists as GONE, "absent at HEAD, no rename found".
    """


class OfflineError(NotCachedError):
    """A request a run that fetches nothing (RETROBIOS_OFFLINE) would have sent."""


class TruncatedListingError(UpstreamError):
    """A listing the forge served in part: a page that could not be read,
    the page cap, or a tree GitHub cut short. What it holds is real, but an
    absence from it proves nothing."""


class GoneError(UpstreamError):
    """The upstream is not coming back.

    A legal takedown, a resource the forge reports as gone, or a host that
    no longer resolves. Retrying costs time and ends in the same place, and
    a caller sweeping every profile wants this told apart from a forge
    having a bad minute: one is a fact about the project, the other is
    weather.
    """


def forge_headers(
    url: str, accept: str | None = None, user_agent: str = USER_AGENT
) -> dict[str, str]:
    """Request headers for a forge URL, the GitHub token on TOKEN_HOSTS only.

    The host is compared whole: a lookalike such as github.com.example or
    a query string naming api.github.com gets no token.
    """
    headers = {"User-Agent": user_agent}
    if accept is not None:
        headers["Accept"] = accept
    if urllib.parse.urlsplit(url).hostname in TOKEN_HOSTS:
        from core.github import github_token

        # GITHUB_TOKEN, else the one gh is logged in with.
        token = github_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers


def _http_failure(url: str, exc: urllib.error.HTTPError) -> UpstreamError:
    """Classify an HTTP error. Only a real quota signal is fatal.

    A forge answering 403 is usually refusing the request, not reporting a
    quota: small Forgejo instances behind anti-bot filters do it routinely.
    GitHub reports exhaustion with X-RateLimit-Remaining: 0, and 429 is the
    standard quota status everywhere, so those two are the only fatal cases.
    """
    host = urllib.parse.urlsplit(url).hostname or ""
    if exc.code == 429:
        retry_after = (exc.headers.get("Retry-After") or "").strip() if exc.headers else ""
        wait = f", retry after {retry_after} s" if retry_after.isdigit() else ""
        return RateLimitError(f"{url}: HTTP 429{wait}", host)
    if exc.code in (410, 451):
        reason = "withdrawn for legal reasons" if exc.code == 451 else "gone"
        return GoneError(f"{url}: HTTP {exc.code}, {reason}")
    if exc.code == 403 and exc.headers is not None:
        remaining = exc.headers.get("X-RateLimit-Remaining")
        if remaining is not None and remaining.strip() == "0":
            return RateLimitError(f"{url}: HTTP 403, quota exhausted", host)
    return UpstreamError(f"{url}: HTTP {exc.code}")


def _host_is_unresolvable(exc: BaseException) -> bool:
    """Whether a connection failure is the name itself, not the network.

    URLError carries the cause in `reason`, and a wrapped one carries it in
    `__cause__`. The walk is bounded because either chain can be cyclic.
    """
    seen: BaseException | None = exc
    for _ in range(8):
        if seen is None:
            break
        if isinstance(seen, socket.gaierror):
            # A resolver that answers nothing at all is the local network:
            # every profile would read as gone, and the sweep would report
            # nothing to review while it reviewed nothing.
            return seen.errno == socket.EAI_NONAME and _resolver_answers()
        nested = getattr(seen, "reason", None)
        seen = nested if isinstance(nested, BaseException) else seen.__cause__
    return False


# A name every forge call depends on: if it does not resolve, the fault is
# local and no host can be declared gone.
RESOLVER_PROBE = "github.com"


def _resolver_answers() -> bool:
    """Whether name resolution works here at all. Replaced in tests."""
    try:
        socket.getaddrinfo(RESOLVER_PROBE, 443)
    except OSError:
        return False
    return True


class _Headers(Protocol):
    def get(self, name: str, /) -> str | None: ...


def requested_wait(headers: _Headers | None) -> float | None:
    """Seconds a 429 asks the client to wait, None when it names none.

    Retry-After is the standard header. GoatCounter sends X-Rate-Limit-Reset
    instead, the whole seconds left in its window, so one more second is
    added: asked again on the second it names, the window is still closed.
    """
    if not headers:
        return None
    retry_after = (headers.get("Retry-After") or "").strip()
    if retry_after.isdigit():
        return float(retry_after)
    reset = (headers.get("X-Rate-Limit-Reset") or "").strip()
    return float(reset) + 1 if reset.isdigit() else None


def _rate_limit_wait(exc: urllib.error.HTTPError, waited: int) -> float | None:
    """Seconds to wait before asking again, or None when waiting is futile.

    GitHub's exhausted quota (403) resets on the hour. A 429 names its wait
    (requested_wait), which is followed up to a cap, else the fixed steps.
    """
    if exc.code != 429 or waited >= len(RATE_LIMIT_WAITS):
        return None
    delay = requested_wait(exc.headers)
    if delay is not None:
        return delay if delay <= RATE_LIMIT_WAIT_CAP else None
    return RATE_LIMIT_WAITS[waited]


class _Readable(Protocol):
    def read(self, size: int = ..., /) -> bytes: ...


def read_limited(resp: _Readable, max_bytes: int = MAX_RESPONSE_SIZE) -> bytes:
    """Read a response whole, ValueError past `max_bytes`."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"Response exceeds {max_bytes} byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def open_retrying(
    request: urllib.request.Request,
    consume: Callable[[http.client.HTTPResponse], _T],
    timeout: float = 30,
) -> _T:
    """Open `request` and hand the response to `consume`.

    A pass over every profile issues thousands of requests, so a dropped
    connection or a transient 5xx is a certainty rather than an accident.
    Those are retried, a definitive answer from the forge is not. A rate
    limit is waited out, and a host that outlasts the waits is not asked
    again in this process. What ends the attempts is raised as urllib gave
    it, except a host that does not resolve (GoneError) and a host muted
    earlier (RateLimitError). A run that fetches nothing (run_is_offline)
    raises OfflineError before anything goes out. A file: address is read
    from this machine and is never refused.
    """
    url = request.full_url
    if run_is_offline() and request.type != "file":
        raise OfflineError(f"{url}: {OFFLINE_ENV} is set, nothing is fetched")
    host = urllib.parse.urlsplit(url).hostname or ""
    if host in _exhausted_hosts:
        raise RateLimitError(f"{url}: {host} rate limited earlier in this run", host)
    attempt = 0
    waited = 0
    while True:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                return consume(resp)
        except urllib.error.HTTPError as exc:
            if isinstance(_http_failure(url, exc), RateLimitError):
                delay = _rate_limit_wait(exc, waited)
                if delay is None:
                    _exhausted_hosts.add(host)
                    raise
                waited += 1
                _sleep(delay)
                continue
            if exc.code < 500:
                raise
            failure: BaseException = exc
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            if _host_is_unresolvable(exc):
                raise GoneError(f"{url}: host does not resolve") from exc
            failure = exc
        attempt += 1
        if attempt >= RETRIES:
            raise failure
        _sleep(RETRY_BACKOFF[attempt - 1])


def fetch_body(
    url: str,
    accept_json: bool = False,
    *,
    timeout: float = 30,
    max_bytes: int = MAX_RESPONSE_SIZE,
    user_agent: str = USER_AGENT,
) -> bytes | None:
    """Body of a GET, or None on 404, retried as open_retrying does.

    A failure raises UpstreamError (RateLimitError, GoneError), a body over
    `max_bytes` ValueError.
    """
    accept = "application/json" if accept_json else None
    req = urllib.request.Request(url, headers=forge_headers(url, accept, user_agent))
    try:
        return open_retrying(req, lambda resp: read_limited(resp, max_bytes), timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise _http_failure(url, exc) from exc
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise UpstreamError(f"{url}: {exc}") from exc


def http_text(url: str) -> str | None:
    """Text body of a GET, or None on 404. Replaced in tests."""
    body = fetch_body(url)
    return None if body is None else body.decode("utf-8", errors="replace")


def remote_etag(url: str, timeout: float = 30) -> str | None:
    """ETag, else Last-Modified, of a HEAD; "" when neither is sent, None
    when the server does not answer."""
    req = urllib.request.Request(
        url, method="HEAD", headers=forge_headers(url, user_agent="retrobios/1.0")
    )
    try:
        return open_retrying(
            req,
            lambda resp: resp.headers.get("ETag") or resp.headers.get("Last-Modified") or "",
            timeout,
        )
    except (urllib.error.URLError, http.client.HTTPException, OSError, UpstreamError):
        return None


class _Refused(Exception):
    """A finished download the caller's check turned down."""


def download(
    url: str,
    destination: str | os.PathLike[str],
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = 300,
    max_bytes: int | None = None,
    user_agent: str = USER_AGENT,
    accept: Callable[[str], bool] | None = None,
) -> http.client.HTTPMessage | None:
    """Stream `url` into `destination`, whole or not at all, and return the
    response headers.

    The body goes to a unique scratch beside the destination, renamed into
    place once complete, so a reader or an interrupted run never sees half a
    file and two runs never interleave their bytes. Each attempt of
    open_retrying starts the scratch over: a stream cut midway is retried
    like a refused connection. `headers` add to or replace forge_headers().
    A body past `max_bytes` raises ValueError. `accept` judges the finished
    scratch by its path: refused, nothing is written and None is returned.
    A failure raises as open_retrying raises it.
    """
    request = urllib.request.Request(
        url, headers={**forge_headers(url, user_agent=user_agent), **(headers or {})}
    )

    def save(scratch: str, resp: http.client.HTTPResponse) -> http.client.HTTPMessage:
        total = 0
        with open(scratch, "wb") as out:
            while chunk := resp.read(1 << 20):
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise ValueError(f"{url}: response exceeds {max_bytes} byte limit")
                out.write(chunk)
        return resp.headers

    try:
        with atomic_scratch(destination) as scratch:
            served = open_retrying(request, lambda resp: save(scratch, resp), timeout)
            if accept is not None and not accept(scratch):
                raise _Refused
    except _Refused:
        return None
    return served


def http_json(url: str) -> object | None:
    """Parsed JSON body of a GET, or None on 404. Replaced in tests."""
    body = fetch_body(url, accept_json=True)
    return None if body is None else json.loads(body.decode())
