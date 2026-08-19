"""Reading JSON from a remote source, under limits that were each measured.

Both the npm registry and OSV sit on the far side of an incident, and every guard
here exists because its absence was observed rather than imagined:

- ``read()`` with no argument returns only at EOF and urllib's timeout is per socket
  operation, so a server sending one byte every half second held the caller open
  indefinitely — measured still running after 12 seconds against a 30-second timeout.
- A gzip or non-UTF-8 body raises ``UnicodeDecodeError``, a truncated one
  ``IncompleteRead``, deeply nested JSON ``RecursionError``. None is caught by the
  CLI's handlers, so all three escaped as a traceback — and this tool's contract
  reads a bare traceback as exit 1, "rotate these credentials".
- ``read1`` returns what has arrived instead of blocking for a full chunk, which is
  what lets a deadline actually be checked. It also means a body cut short simply
  ends where ``read()`` would have raised, so a declared length is verified.

Nothing on the scan path imports this. A verdict must not depend on a network the
incident may itself have taken down.
"""
from __future__ import annotations

import json
import ssl
import time as _time
import urllib.error
import urllib.request

from . import __version__

# Per socket operation, so this is also the stall budget: a connection that goes
# quiet raises TimeoutError from the next read, measured at 2.0s with TIMEOUT=2.0.
TIMEOUT = 30.0

# What TIMEOUT cannot catch is a connection that never stops and never finishes,
# because a trickle resets it forever. next's packument is 31MB, so this has to be
# long enough for that over a slow link and short enough to be an answer.
DEADLINE = 900.0

# Measured, not guessed: next is 31,118,994 bytes, firebase 30,213,522, npm
# 25,470,903. An earlier 32 MiB cap was already 92.7% consumed by next.
MAX_BYTES = 256 * 1024 * 1024


class FetchError(RuntimeError):
    """A remote source could not answer, or answered something unusable.

    Carries the HTTP status when there was one, so a caller can add advice that only
    makes sense for its own source — "no such package" means something different to
    the registry than to an advisory database.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def read_json(url: str, *, label: str, opener=None,
              timeout: float | None = None) -> object:
    """Fetch one JSON document. ``opener`` is injectable so tests stay offline.

    Both ``opener`` and ``timeout`` are resolved when called rather than bound as
    defaults: a default argument captures the value at import, so a test that lowers
    ``TIMEOUT`` to prove a stall is caught was silently ignored — and hung past its
    own deadline proving it.
    """
    opener = opener or urllib.request.urlopen
    timeout = TIMEOUT if timeout is None else timeout
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"deptrail/{__version__}",
                 "Accept": "application/json"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            raw = read_bounded(response, label)
    except urllib.error.HTTPError as e:
        raise FetchError(f"{label}: {url} answered HTTP {e.code}", status=e.code) from e
    except urllib.error.URLError as e:
        # A missing trust store is not a network outage, and "could not reach it"
        # sends the reader to inspect a firewall that is fine. Python installed from
        # python.org ships no CA bundle until its own Install Certificates step runs,
        # which is a fresh macOS machine's default state — measured here.
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            raise FetchError(
                f"{label}: the certificate for {url} could not be verified, which "
                "usually means this Python has no CA bundle rather than that the host "
                "is unreachable. On a python.org install run "
                "'Install Certificates.command', or point SSL_CERT_FILE at a bundle "
                f"(e.g. /etc/ssl/cert.pem). Underlying error: {e.reason}"
            ) from e
        raise FetchError(f"{label}: could not reach {url}: {e.reason}") from e

    try:
        return json.loads(raw)
    except Exception as e:
        raise FetchError(
            f"{label}: the answer from {url} could not be read as JSON "
            f"({type(e).__name__}: {e})"
        ) from e


def read_bounded(response, name: str) -> bytes:
    """Read a response under both a size cap and a wall clock.

    ``read()`` with no argument returns only at EOF, and urllib's timeout is per
    socket operation — so a server sending one byte every half second holds the
    importer open forever. Measured: a 30-second TIMEOUT was still running after 12
    seconds against exactly that.

    ``read1`` returns whatever has arrived rather than blocking for a full chunk,
    which is what lets the deadline below actually be checked. An injected opener in
    a test may only offer ``read``, and for those the single call is the whole body.
    """
    def too_big(size: int) -> RegistryError:
        return FetchError(
            f"{name}: the registry's answer exceeded {MAX_BYTES} bytes "
            f"({size} so far). The largest packument measured is next at about 31MB, "
            "so this is either a much larger package than any seen or a broken "
            "response; retrying will not change it."
        )

    def stopped_early(e: Exception) -> RegistryError:
        # A connection dropped mid-read raises http.client.IncompleteRead, which is
        # neither an OSError nor caught by `main()`.
        return FetchError(
            f"{name}: the registry's answer stopped early "
            f"({type(e).__name__}: {e})"
        )

    declared = None
    header = getattr(response, "headers", None)
    if header is not None:
        try:
            declared = int(header.get("Content-Length"))
        except (TypeError, ValueError):
            declared = None

    reader = getattr(response, "read1", None)
    if reader is None:
        # An injected opener in a test may only offer `read`; the cap still applies,
        # because "the fallback is only for tests" is exactly the assumption that
        # stops being true later.
        try:
            raw = response.read(MAX_BYTES + 1)
        except Exception as e:
            raise stopped_early(e) from e
        if len(raw) > MAX_BYTES:
            raise too_big(len(raw))
        return raw

    started = _time.monotonic()
    chunks, size = [], 0
    while True:
        if _time.monotonic() - started > DEADLINE:
            raise FetchError(
                f"{name}: the registry was still sending after {DEADLINE:.0f}s "
                f"({size} bytes so far); giving up rather than hanging"
            )
        try:
            chunk = reader(65536)
        except Exception as e:
            raise stopped_early(e) from e
        if not chunk:
            # `read1` returns what has arrived, so a body cut short simply ends —
            # where `read()` would have raised IncompleteRead. Without this a
            # truncated packument parses as far as it got, or fails as bad JSON,
            # and either way the reason is lost.
            if declared is not None and size != declared:
                raise FetchError(
                    f"{name}: the registry declared {declared} bytes and sent {size}"
                )
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_BYTES:
            raise too_big(size)
        chunks.append(chunk)


