"""Reading a malicious package's version list out of OSV.

The other half of an advisory. ``registry.py`` answers *when* a version was
installable; this answers *which versions were malicious* — and it matters that the
answer comes from somewhere citable rather than from a responder's keyboard.

#10 records what hand-entry costs. The first hand-written feed for this tool took its
window from a vendor blog's attacker-activity times while the malicious versions
appeared hours later, so the feed could only ever return CLEAN. It was deleted rather
than shipped. A version list is the same hazard one field over: a version typed
slightly wrong matches no lockfile entry, and a package silently missing from the
list is a repository silently cleared.

OSV publishes one ``MAL-`` record per compromised package, with the exact versions in
``affected[].versions``. Measured against the September 2025 compromise: chalk is
MAL-2025-46969 with ``["5.6.1"]``, debug MAL-2025-46974 with ``["4.4.2"]``,
ansi-styles MAL-2025-46967 with ``["6.2.2"]``, all published 2025-09-08.

What this module does *not* do is decide which packages belong to an incident. OSV
has no notion of one — there is no query that returns "everything compromised on this
day". The set of names stays an input, cited to the writeup it came from, and every
name in it is checked here: a name OSV has no malicious record for stops the import
rather than quietly contributing nothing.

Nothing on the scan path imports this.
"""
from __future__ import annotations

from dataclasses import dataclass

from .fetch import FetchError, read_json

OSV = "https://api.osv.dev/v1"

# OSV's own prefix for a malicious-package record, as opposed to a vulnerability in
# otherwise honest code. Only these are of interest: DepTrail judges compromise, and a
# CVE in a library that was never hijacked is a different tool's job.
MALICIOUS_PREFIX = "MAL-"


class OsvError(FetchError):
    """OSV could not answer, or answered something unusable."""


@dataclass(frozen=True)
class MaliciousRelease:
    """One OSV record's verdict about one package."""

    package: str
    versions: tuple[str, ...]
    advisory_id: str
    aliases: tuple[str, ...]
    published: str
    references: tuple[str, ...]

    @property
    def source(self) -> str:
        """The record itself, which is what an advisory should cite."""
        return f"{OSV}/vulns/{self.advisory_id}"


def query_url() -> str:
    return f"{OSV}/query"


def _post_json(url: str, payload: dict, *, label: str, opener=None,
               timeout: float | None = None) -> object:
    """OSV's query endpoint is a POST, which `read_json` does not do on its own."""
    import json
    import urllib.request

    from . import __version__

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"User-Agent": f"deptrail/{__version__}",
                 "Accept": "application/json",
                 "Content-Type": "application/json"},
    )

    # Reuses the transport's limits and error wrapping by handing it a prepared
    # request: everything learned about trickles, truncation and undecodable bodies
    # applies to OSV exactly as it does to the registry.
    def prepared(_ignored, timeout=None):
        return (opener or urllib.request.urlopen)(request, timeout=timeout)

    return read_json(url, label=label, source="OSV", opener=prepared,
                     timeout=timeout)


def malicious_releases(name: str, *, opener=None,
                       timeout: float | None = None) -> tuple[MaliciousRelease, ...]:
    """Every malicious-package record OSV holds for this package.

    Returns them all rather than picking one. A package compromised twice has two
    records, and choosing between them is the operator's call — this module will not
    guess which incident is being responded to.
    """
    try:
        answer = _post_json(query_url(),
                            {"package": {"name": name, "ecosystem": "npm"}},
                            label=name, opener=opener, timeout=timeout)
    except FetchError as e:
        raise OsvError(str(e), status=e.status) from e

    if not isinstance(answer, dict):
        raise OsvError(f"{name}: OSV's answer was not an object")
    records = answer.get("vulns") or []
    if not isinstance(records, list):
        raise OsvError(f"{name}: OSV's 'vulns' was not a list")

    found = []
    for record in records:
        if not isinstance(record, dict):
            raise OsvError(f"{name}: OSV returned a record that was not an object")
        identifier = record.get("id")
        if not isinstance(identifier, str) or not identifier.startswith(MALICIOUS_PREFIX):
            continue
        versions = _affected_versions(record, name)
        if not versions:
            # Skipping would drop the package from the advisory without saying so, but
            # *why* there is nothing to take decides the operator's next move, and the
            # two cases point opposite ways.
            raise OsvError(_nothing_to_take(record, name, identifier))
        found.append(MaliciousRelease(
            package=name,
            versions=versions,
            advisory_id=identifier,
            aliases=tuple(a for a in (record.get("aliases") or []) if isinstance(a, str)),
            published=record.get("published") or "",
            references=tuple(
                r["url"] for r in (record.get("references") or [])
                if isinstance(r, dict) and isinstance(r.get("url"), str)
            ),
        ))
    return tuple(found)


def _whole_package_ranges(record: dict, name: str) -> bool:
    """Whether this record says every version of the package is malicious.

    OSV writes that as a range introduced at ``0`` with no fix, which is how a
    typosquat is recorded — the package was never anything but malicious, so there is
    no version list to give. Measured: 5 of roughly 40 consecutive ``MAL-`` records
    sampled from 2025-09 are this shape, so it is ordinary rather than exotic.
    """
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("name") != name:
            continue
        for entry in affected.get("ranges") or []:
            if not isinstance(entry, dict):
                continue
            for event in entry.get("events") or []:
                if isinstance(event, dict) and event.get("introduced") == "0":
                    return True
    return False


def _nothing_to_take(record: dict, name: str, identifier: str) -> str:
    """Say which of the two shapes this is, because the fix differs.

    The earlier message said the record "names no affected version" in both cases.
    For a whole-package record that is the opposite of true — it names every version
    — and an operator who went to read it found a range and no list.
    """
    where = f"{OSV}/vulns/{identifier}"
    if _whole_package_ranges(record, name):
        return (
            f"{name}: {identifier} says every version of this package is malicious, "
            "not a specific one. This advisory schema matches lockfile entries by "
            "exact version, so it cannot carry 'all of them'. List the versions the "
            "registry published — https://registry.npmjs.org/" + name + " — and pass "
            f"them with --package. Tracked as #68. Record: {where}"
        )
    return (
        f"{name}: {identifier} names no affected version at all, so there is nothing "
        f"to judge a lockfile against. Read the record and decide: {where}"
    )


def _affected_versions(record: dict, name: str) -> tuple[str, ...]:
    """Versions this record names for this package, and no other package's.

    An OSV record can carry several `affected` entries; matching on the package name
    keeps a record that mentions a neighbour from contributing its versions here.
    """
    versions: list[str] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("name") != name:
            continue
        for version in affected.get("versions") or []:
            if isinstance(version, str) and version not in versions:
                versions.append(version)
    return tuple(versions)
