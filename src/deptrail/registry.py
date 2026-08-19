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
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from . import __version__

REGISTRY = "https://registry.npmjs.org"

# The registry is a third party on the far side of an incident; a hung socket must
# not become a hung importer.
TIMEOUT = 30.0

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


def packument_url(name: str) -> str:
    """The full packument, which is the only form carrying ``time``.

    The abbreviated form (``Accept: application/vnd.npm.install-v1+json``) is a
    third of the size and has no ``time`` map at all — measured on chalk, debug and
    ansi-styles — so there is nothing to save here.

    A scoped name's slash belongs to the name rather than to the path, so the whole
    name is escaped. The registry accepts every escaping of ``@babel/core`` tried.
    """
    return f"{REGISTRY}/{urllib.parse.quote(name, safe='')}"


def fetch_packument(name: str, *, opener=None, timeout: float = TIMEOUT) -> dict:
    """Read one package's packument. ``opener`` is injectable so tests stay offline.

    Resolved at call time rather than bound as a default: a default argument captures
    ``urllib.request.urlopen`` when this module is imported, so a test that replaces
    that attribute to prove nothing reaches the network would be quietly ignored.
    """
    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(
        packument_url(name),
        headers={"User-Agent": f"deptrail/{__version__}",
                 "Accept": "application/json"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read()
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
    except json.JSONDecodeError as e:
        raise RegistryError(f"{name}: the registry's answer was not JSON: {e}") from e
    if not isinstance(packument, dict):
        raise RegistryError(f"{name}: the registry's answer was not an object")
    return packument


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


def publish_records(packument: dict, name: str,
                    versions: tuple[str, ...]) -> tuple[PublishRecord, ...]:
    """When each named version was first published.

    A version the registry has no time for stops the import. It is tempting to skip
    it and carry on with the rest, but a malicious version silently missing from an
    advisory is the difference between a repository being reported and being cleared
    — the failure would arrive as a confident CLEAN months later.
    """
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
        records.append(PublishRecord(
            name=name,
            version=version,
            published_at=_published_at(stamp, f"{name}@{version}"),
            still_served=version in served,
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


def advisory_from_records(records: tuple[PublishRecord, ...], *, identifier: str,
                          name: str, sources: tuple[str, ...],
                          coverage: str = "partial",
                          notes: str | None = None) -> dict:
    """Assemble an advisory whose every window start is a registry publish time.

    Pure: it makes no request, so the shape this produces can be tested without a
    network and the request that produced ``records`` can be tested separately.

    Versions of one package published at the same instant share an entry. Versions
    published at different instants become separate entries, which is what the
    schema calls a wave — the September 2025 compromise published ``ansi-styles``
    6.2.2 at 13:12:10, ``debug`` 4.4.2 at 13:12:39 and ``chalk`` 5.6.1 at 13:13:05,
    and collapsing those into one start would report each package as installable
    before it existed.

    Every ``end`` is ``null``. No removal time is recorded anywhere in the registry,
    and the whole point of this importer is to stop that blank being filled in by
    hand with something plausible.
    """
    if not records:
        raise RegistryError("no versions to derive a window from")

    waves: dict[tuple[str, datetime], list[str]] = {}
    for record in records:
        waves.setdefault((record.name, record.published_at), []).append(record.version)

    # The advisory window has to contain every package window, so it opens at the
    # earliest publish instant among them.
    earliest = min(moment for _, moment in waves)
    opener = next(pkg for pkg, moment in waves if moment == earliest)

    def window(moment: datetime, package: str) -> dict:
        source = packument_url(package)
        return {
            "start": moment.isoformat(),
            "end": None,
            "provenance": {
                # Read from this packument's `time` map, which keeps the entry after
                # the version is withdrawn.
                "start": {"kind": "derived", "source": source},
                # The same document is where the absence of a removal time was
                # observed, which is why it is cited for a bound that does not exist.
                "end": {"kind": "unknown", "source": source},
            },
        }

    packages = []
    for (package, moment), versions in sorted(waves.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        served = [r for r in records if r.name == package and r.published_at == moment
                  and r.still_served]
        entry = {
            "name": package,
            "versions": sorted(versions),
            "sources": [packument_url(package)],
            "notes": (
                "Window start read from the registry's publish time. The end is null "
                "because npm records no removal time. "
                + ("This version is still being served, so it remains installable."
                   if served else
                   "This version is no longer served, so removal happened at or "
                   "before the moment this advisory was derived — that is an upper "
                   "bound on the end, not the end.")
            ),
        }
        # Only when it differs: an entry repeating the advisory's own window would
        # read as a second wave at the same instant, which the loader rejects.
        if moment != earliest:
            entry["window"] = window(moment, package)
        packages.append(entry)

    return {
        "schema_version": 2,
        "id": identifier,
        "name": name,
        "ecosystem": "npm",
        "coverage": coverage,
        "window": window(earliest, opener),
        "packages": packages,
        "sources": list(sources),
        "notes": notes or (
            "Window starts derived from registry publish times; ends left unknown "
            "because no registry records a removal time."
        ),
    }
