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

import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from .fetch import FetchError, read_json

REGISTRY = "https://registry.npmjs.org"

# `time` holds these two alongside one entry per version.
_NOT_A_VERSION = frozenset({"created", "modified"})


class RegistryError(FetchError):
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
    """Read one package's packument. ``opener`` is injectable so tests stay offline."""
    try:
        packument = read_json(packument_url(name), label=name,
                              opener=opener, timeout=timeout)
    except FetchError as e:
        if e.status == 404:
            raise RegistryError(
                f"{name}: the registry has no such package. A package name that "
                "does not resolve cannot be the one that was compromised — check "
                "the spelling and the scope rather than dropping the entry."
            ) from e
        raise RegistryError(str(e)) from e
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


def _entry_notes(package: str, versions: list[str], moment: datetime,
                 records: tuple[PublishRecord, ...], derived_at: str) -> str:
    """What is true of this entry, per version rather than as one sweeping claim."""
    mine = {r.version: r for r in records if r.name == package and r.published_at == moment}
    served = sorted(v for v in versions if mine[v].still_served)
    gone = sorted(v for v in versions if not mine[v].still_served)
    relabelled = sorted(v for v in versions if mine[v].dated_from not in ("", v))

    parts = ["Window start read from the registry's publish time; the end is null "
             "because npm records no per-version removal time."]
    if served:
        parts.append(f"Still served as of {derived_at}: {', '.join(served)}.")
    if gone:
        parts.append(
            f"No longer served as of {derived_at}: {', '.join(gone)} — so removal "
            "happened at or before that instant, which is an upper bound on the end "
            "and not the end.")
    if relabelled:
        detail = ", ".join(f"{v} dated from the earlier key {mine[v].dated_from!r}"
                           for v in relabelled)
        parts.append(
            f"npm re-keyed a legacy version here, so the later entry is the "
            f"re-keying instant rather than the publish: {detail}.")
    return " ".join(parts)


def advisory_from_records(records: tuple[PublishRecord, ...], *, identifier: str,
                          name: str, sources: tuple[str, ...],
                          coverage: str = "partial",
                          notes: str | None = None,
                          derived_at: datetime | None = None) -> dict:
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
    # Stamped into the notes: the withdrawn/served split below is a claim about one
    # instant, and a reader months later cannot weigh it without knowing which.
    derived_at = (derived_at or datetime.now(timezone.utc)).isoformat()

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
        entry = {
            "name": package,
            "versions": sorted(versions),
            "sources": [packument_url(package)],
            "notes": _entry_notes(package, versions, moment, records, derived_at),
        }
        # Always, not only when it differs from the advisory's. Two packages published
        # in the same millisecond — a scripted mass-publish, which is what Shai-Hulud
        # was — would otherwise both inherit a window citing whichever packument sorted
        # first, so one package's start would be sourced to another's document. The
        # loader accepts an explicit copy: `(name, start)` is unchanged, so it is not
        # read as a second wave.
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
