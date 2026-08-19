"""Reading publish times out of an npm packument.

This module answers one question, the only one the registry can answer about the
past: *when was this exact version first published?* That instant is the left edge
of the interval the artifact was installable, and it survives an unpublish — the
per-version entry stays in the packument's ``time`` map after the version is gone
from ``versions``.

It deliberately answers no others. In particular it never reports a removal time,
because npm records none: measured against ``registry.npmjs.org`` on 2026-08-19,
``chalk`` 5.6.1, ``debug`` 4.4.2 and ``ansi-styles`` 6.2.2 are each absent from
``versions``, present in ``time``, and carry no ``unpublished`` key anywhere. The
right edge stays unknown, which the advisory schema can say out loud.

**Nothing on the scan path imports this.** A verdict must not depend on a network
the incident may itself have taken down, and a window that differs between two
runs of the same scan is not evidence — it is a moving target. Deriving happens
once, into a file a human reads, and the scan reads the file.
"""
from __future__ import annotations

import json
import ssl
import time as _time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from . import __version__

REGISTRY = "https://registry.npmjs.org"

# urllib's timeout is per socket operation, not a deadline: a server dribbling one
# byte at a time resets it forever, and a 30-second TIMEOUT was measured still
# running after 12 seconds of that with no way to tell it was stuck. So the read is
# chunked with a wall clock over it.
TIMEOUT = 30.0

# TIMEOUT is per socket operation, so it is already the stall budget: a connection
# that goes quiet raises TimeoutError from the next read, measured at 2.0s with
# TIMEOUT=2.0. What it cannot catch is a connection that never stops and never
# finishes, because a trickle resets it forever — that is DEADLINE's job, and the two
# are not interchangeable.
DEADLINE = 900.0

# Measured against the live registry rather than guessed from the three small packages
# this importer was first tried on: next is 31,118,994 bytes, firebase 30,213,522, npm
# 25,470,903. An earlier 32 MiB cap was already 92.7% consumed by next and would have
# begun rejecting it within months, as exit 4 "retry may help" for a condition no
# retry can fix.
MAX_BYTES = 256 * 1024 * 1024

# `time` holds these two alongside one entry per version.
_NOT_A_VERSION = frozenset({"created", "modified"})


class RegistryError(RuntimeError):
    """The registry could not answer, or answered something unusable.

    Never raised for an answer we merely dislike: a version the registry says was
    never published is a fact, and it is reported as one.
    """


@dataclass(frozen=True)
class PublishRecord:
    """When one version first appeared, and whether it is still being served."""

    name: str
    version: str
    published_at: datetime

    # Absence from `versions` proves removal happened at or before the moment this
    # was read. That is a true upper bound on the right edge and a useless one — it
    # is the read time, not the removal time, and for a year-old incident it is a
    # year too late. It is carried as corroboration that a version was withdrawn at
    # all, never as a window end.
    still_served: bool

    # Which key in `time` the instant came from. Differs from `version` only when npm
    # re-keyed a legacy version and kept the original entry; see `_legacy_keys`.
    dated_from: str = ""


def packument_url(name: str) -> str:
    """The full packument, which is the only form carrying ``time``.

    The abbreviated form (``Accept: application/vnd.npm.install-v1+json``) is a
    third of the size and has no ``time`` map at all — measured on chalk, debug and
    ansi-styles — so there is nothing to save here.

    A scoped name's slash belongs to the name rather than to the path, so the whole
    name is escaped. The registry accepts every escaping of ``@babel/core`` tried.
    """
    return f"{REGISTRY}/{urllib.parse.quote(name, safe='')}"


def fetch_packument(name: str, *, opener=None, timeout: float | None = None) -> dict:
    """Read one package's packument. ``opener`` is injectable so tests stay offline.

    Resolved at call time rather than bound as a default: a default argument captures
    ``urllib.request.urlopen`` when this module is imported, so a test that replaces
    that attribute to prove nothing reaches the network would be quietly ignored.
    """
    opener = opener or urllib.request.urlopen
    # Same reason as the opener: `timeout=TIMEOUT` as a default captures the value at
    # import, so raising or lowering it later — including in a test that means to prove
    # a stalled connection is caught — has no effect at all.
    timeout = TIMEOUT if timeout is None else timeout
    request = urllib.request.Request(
        packument_url(name),
        headers={"User-Agent": f"deptrail/{__version__}",
                 "Accept": "application/json"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            raw = _read_bounded(response, name)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RegistryError(
                f"{name}: the registry has no such package. A package name that "
                "does not resolve cannot be the one that was compromised — check "
                "the spelling and the scope rather than dropping the entry."
            ) from e
        raise RegistryError(f"{name}: the registry answered HTTP {e.code}") from e
    except urllib.error.URLError as e:
        # A missing trust store is not a network outage, and saying "could not reach
        # the registry" sends the reader to look at their firewall. Python installed
        # from python.org ships no CA bundle until its own Install Certificates step
        # is run, which is a fresh macOS machine's default state — measured here.
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            raise RegistryError(
                f"{name}: the registry's certificate could not be verified, which "
                "usually means this Python has no CA bundle rather than that the "
                "registry is unreachable. On a python.org install run "
                "'Install Certificates.command', or point SSL_CERT_FILE at a bundle "
                f"(e.g. /etc/ssl/cert.pem). Underlying error: {e.reason}"
            ) from e
        raise RegistryError(f"{name}: could not reach the registry: {e.reason}") from e

    try:
        packument = json.loads(raw)
    # Not just JSONDecodeError. A gzip or non-UTF-8 body raises UnicodeDecodeError and
    # deeply nested JSON raises RecursionError; neither is caught by `main()`, so both
    # used to leave as an uncaught traceback — which this contract reads as exit 1,
    # "rotate these credentials". Measured on all three.
    except Exception as e:
        raise RegistryError(
            f"{name}: the registry's answer could not be read as JSON "
            f"({type(e).__name__}: {e})"
        ) from e
    if not isinstance(packument, dict):
        raise RegistryError(f"{name}: the registry's answer was not an object")
    return packument


def _read_bounded(response, name: str) -> bytes:
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
        return RegistryError(
            f"{name}: the registry's answer exceeded {MAX_BYTES} bytes "
            f"({size} so far). The largest packument measured is next at about 31MB, "
            "so this is either a much larger package than any seen or a broken "
            "response; retrying will not change it."
        )

    def stopped_early(e: Exception) -> RegistryError:
        # A connection dropped mid-read raises http.client.IncompleteRead, which is
        # neither an OSError nor caught by `main()`.
        return RegistryError(
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
            raise RegistryError(
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
                raise RegistryError(
                    f"{name}: the registry declared {declared} bytes and sent {size}"
                )
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_BYTES:
            raise too_big(size)
        chunks.append(chunk)


def _published_at(stamp: object, where: str) -> datetime:
    if not isinstance(stamp, str):
        raise RegistryError(f"{where}: publish time is {type(stamp).__name__}, not a string")
    try:
        # npm writes Zulu, which fromisoformat only learned to parse in 3.11.
        moment = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
    except ValueError as e:
        raise RegistryError(f"{where}: publish time {stamp!r} is not a timestamp: {e}") from e
    if moment.tzinfo is None:
        raise RegistryError(f"{where}: publish time {stamp!r} carries no timezone")
    return moment.astimezone(timezone.utc)


def _legacy_keys(times: dict, served: dict, version: str) -> tuple[str, ...]:
    """Other keys in ``time`` that name the same artifact as ``version``.

    npm re-keyed its legacy versions when it normalized them to SemVer, and the new
    key is dated *when the re-keying happened*, not when the artifact was published.
    ``express`` carries 28 such pairs: ``time["1.0.0-beta"]`` is 2013-08-28 while
    ``time["1.0.0beta"]`` is 2010-12-29, and the tarball behind both is
    ``express-1.0.0beta.tgz``. Deriving from the later key starts the window two and a
    half years after the artifact was installable, so an install in between is
    reported CLEAN — the one outcome this tool exists to prevent.

    Ignoring hyphens alone does not identify the pair. It also conflates ``X.Y.Z-N``
    with ``X.Y.ZN``, and ``x.y.z-0`` is exactly what ``npm version prerelease`` emits,
    so that collision is structural rather than exotic. Measured: ``phantomjs`` has
    ``1.9.20`` and ``1.9.2-0`` as separate published artifacts with different shasums
    934 days apart, and on a 700-package sample the hyphen rule fired 8 times and was
    wrong all 8.

    The discriminator is that a re-keying leaves the old spelling in ``time`` only,
    because npm moved the artifact to the new key — while two real releases each keep
    an entry in ``versions``. That rule keeps all 28 express pairs and rejects every
    false positive measured.
    """
    flat = version.replace("-", "")
    return tuple(sorted(k for k in times
                        if k not in _NOT_A_VERSION and k != version
                        and k not in served
                        and k.replace("-", "") == flat))


def publish_records(packument: dict, name: str,
                    versions: tuple[str, ...]) -> tuple[PublishRecord, ...]:
    """When each named version was first published.

    A version the registry has no time for stops the import. It is tempting to skip
    it and carry on with the rest, but a malicious version silently missing from an
    advisory is the difference between a repository being reported and being cleared
    — the failure would arrive as a confident CLEAN months later.
    """
    # A mirror alias, a redirect, or a poisoned cache can all hand back a document
    # for a different package, and every field below would then be read from it.
    declared = packument.get("name")
    if isinstance(declared, str) and declared != name:
        raise RegistryError(
            f"{name}: the registry returned a packument for {declared!r} instead. "
            "Refusing to date one package's versions from another's document."
        )
    times = packument.get("time")
    if not isinstance(times, dict):
        raise RegistryError(f"{name}: the packument carries no 'time' map")
    served = packument.get("versions")
    if not isinstance(served, dict):
        raise RegistryError(f"{name}: the packument carries no 'versions' map")

    records = []
    for version in versions:
        stamp = times.get(version)
        if stamp is None:
            raise RegistryError(
                f"{name}@{version}: the registry records no publish time for this "
                "version, so it was never published and cannot have been installed. "
                "Fix the version string rather than dropping it."
            )
        published_at = _published_at(stamp, f"{name}@{version}")
        legacy = ""
        for other in _legacy_keys(times, served, version):
            earlier = _published_at(times[other], f"{name}@{other}")
            if earlier < published_at:
                # The earliest key wins. Over-reporting is a cost; starting the
                # window after the artifact was already installable is a miss.
                published_at, legacy = earlier, other
        records.append(PublishRecord(
            name=name,
            version=version,
            published_at=published_at,
            still_served=version in served,
            dated_from=legacy or version,
        ))
    return tuple(records)


def withdrawn_versions(packument: dict) -> tuple[str, ...]:
    """Versions the packument remembers publishing but no longer serves.

    Useful only for cross-checking a hand-transcribed list against the registry, and
    never as the list itself: ``ansi-styles`` shows why. It has two withdrawn
    versions, 6.2.2 from the September 2025 compromise and 2.2.0 from 2016.
    Withdrawn is not the same as malicious.
    """
    times = packument.get("time")
    served = packument.get("versions")
    if not isinstance(times, dict) or not isinstance(served, dict):
        return ()
    return tuple(sorted(v for v in times if v not in _NOT_A_VERSION and v not in served))
