"""Advisory (IOC) input format: what a vendor publishes, in a form the walker can judge.

Two hard rules shape this module, both learned from the walker's review:

- **Nothing is inferred.** No default window, no guessed timezone, no version
  ranges. A hand-transcribed feed with a typo'd key fails loudly rather than
  scanning for the wrong thing; every unknown key is an error, not a shrug.
- **Coverage is part of the evidence.** Advisories are published incrementally,
  so a feed declares whether its package list is ``complete`` or ``partial``.
  A partial feed can prove exposure but can never prove its absence, so the
  caveat travels with the work: consumers scan an ``Advisory.plan()``, whose
  ``coverage_warning`` and ``proves_absence`` cannot be dropped by accident.

A window is the interval in which the malicious artifact was **installable** —
first malicious publish until the registry removed it — not the interval in which
the attacker was active. Vendors usually publish the latter, and the two differ
by hours: the TanStack wave's CI compromise ran 11:29-19:15 UTC while the
poisoned versions only appeared at 19:20 and later, so a feed transcribing the
attacker-activity window could only ever return CLEAN. The end bound must be a
time the artifact was no longer installable — not the advisory's publication
time, which is typically hours before removal — and when it is not published, a
deliberately late bound is the safe error: a wide window over-reports exposure,
a narrow one hides it.

A window's **start** is derivable and its **end** is not. A registry packument
keeps ``time[version]`` after the version is unpublished — measured against
``registry.npmjs.org`` for chalk 5.6.1, debug 4.4.2 and ansi-styles 6.2.2, each
present in ``time`` and absent from ``versions`` — so the first malicious publish
is a recorded fact. Nothing anywhere records when the registry stopped serving it.
So ``window.end`` may be ``null``, meaning "not known to have closed", and that is
the honest default rather than an edge case. An open end over-reports exposure; a
guessed closed one hides it, and only one of those errors is recoverable.

``end`` must still be *present*. An omitted key is indistinguishable from a typo,
and this module infers nothing: writing ``null`` is a decision a reader can see.

Windows are inclusive on both ends and must be written as full ISO-8601
timestamps with a UTC offset — no bare dates, because deciding which instants a
published date covers is a judgment that belongs in the feed, visible to whoever
reads the report.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .history import WindowQuery

FEEDS_DIR = Path(__file__).parent / "feeds"
SCHEMA_VERSION = 2
COVERAGE_VALUES = ("complete", "partial")
PROVENANCE_VALUES = ("operator-supplied", "derived", "unknown")

# npm's own name rule (lowercase since 2014) and strict ASCII SemVer, which is
# what a lockfile records. Everything is ASCII-anchored on purpose: a full-width
# "５.６.１" or a two-part "1.0" would pass a looser pattern, match no lockfile
# entry, and read as CLEAN.
_NPM_NAME = re.compile(r"^(?:@[a-z0-9-~][a-z0-9._~-]*/)?[a-z0-9-~][a-z0-9._~-]*$", re.ASCII)
_NPM_NAME_RESERVED = {"node_modules", "favicon.ico"}
_NPM_NAME_MAX = 214
_SEMVER = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
    re.ASCII,
)
_URL = re.compile(r"^https?://\S+$", re.ASCII)
# A bound must name the second it happens at; fromisoformat would otherwise
# zero-fill a missing field and quietly move the edge of the window.
_HAS_SECONDS = re.compile(r"[T ]\d{2}:\d{2}:\d{2}", re.ASCII)

_ADVISORY_KEYS = {
    "schema_version", "id", "name", "ecosystem", "window", "coverage",
    "packages", "sources", "notes",
}
_PACKAGE_KEYS = {"name", "versions", "window", "sources", "notes"}
_WINDOW_KEYS = {"start", "end", "provenance"}
_PROVENANCE_KEYS = {"start", "end"}
_BOUND_PROVENANCE_KEYS = {"kind", "source"}


# The marker ``advisory init`` writes into every field it was not given. The *loader*
# knows it, not just the generator: a blank left anywhere must fail, and checking only the
# fields that happen to have a format (a window, a URL) let an advisory validate with no
# identity at all — it printed "REPLACE-ME — REPLACE-ME" and exited 0.
PLACEHOLDER = "REPLACE-ME"


# The one place this module consults a clock, and the reason is that `start <= end` used
# to catch a mistyped year for free and cannot when the end is open. The slack is for the
# scanner host, not for the feed: a machine minutes or hours off still works, while the
# error this exists to catch is off by a year.
_CLOCK_SLACK = timedelta(days=1)


class IocError(ValueError):
    """The advisory input is malformed. Never raised for merely surprising data."""


@dataclass(frozen=True)
class BoundProvenance:
    """How one edge entered the advisory snapshot, and the exact source used."""

    kind: str
    source: str


@dataclass(frozen=True)
class WindowProvenance:
    """Independent provenance for the start and end of one window."""

    start: BoundProvenance
    end: BoundProvenance


@dataclass(frozen=True)
class InstallableWindow:
    """One installable interval and the provenance of both bounds."""

    start: datetime
    end: datetime | None
    provenance: WindowProvenance


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IocError(message)


def _reject_placeholder(value: object, where: str) -> None:
    """Refuse a field still holding the template's marker."""
    if isinstance(value, str) and PLACEHOLDER in value:
        raise IocError(
            f"{where}: still holds {PLACEHOLDER} — fill it in. An advisory with blanks "
            "must not validate, because a verdict would then rest on a field nobody set"
        )


def _reject_unknown(obj: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(obj) - allowed)
    _require(not unknown, f"{where}: unknown field(s) {unknown}; allowed {sorted(allowed)}")


# Spellings a responder reaches for when they mean "nobody recorded it". Answering
# these with a timestamp hint sends them off to invent one, which is the error that
# hides exposure.
_MEANT_UNKNOWN = frozenset({
    "null", "none", "nil", "nan", "unknown", "unknowable", "open", "n/a", "na", "tbd",
    "?", "-", "--", "not known", "no removal", "never", "ongoing", "still open",
})


def _clip(value: object, limit: int = 80) -> str:
    """A value quoted for an error message, never long enough to bury the message.

    An unbounded ``repr`` turned one mistyped field into a 100,140-character error
    whose first line — the field path, the only part that says what to fix — scrolled
    away.
    """
    shown = repr(value)
    return shown if len(shown) <= limit else f"{shown[:limit]}… ({len(shown)} chars)"


def _parse_bound(value: object, *, where: str) -> datetime:
    """Parse one window bound: a full ISO-8601 timestamp with a UTC offset.

    Nothing is widened or defaulted. A bare date is rejected rather than turned
    into midnight in a timezone we picked — if a vendor publishes only a date,
    the person transcribing it decides which instants the day covers, and that
    decision belongs in the feed where a reader can see it.
    """
    _require(isinstance(value, str) and str(value).strip() != "",
             f"{where}: must be a full timestamp such as 2025-09-08T13:13:05+00:00"
             + (", or unquoted null if the removal time is unknown"
                if where.endswith(".end") else ""))
    text = str(value).strip().replace("Z", "+00:00")
    # Before any shape test. The spellings without a `T` in them — `null`, `unknown`,
    # `n/a`, `-` — fall into the time-of-day branch, and a check ordered after it would
    # answer them with a hint built by slicing the junk: "write nullT00:00:00+00:00".
    if where.endswith(".end") and text.strip().lower() in _MEANT_UNKNOWN:
        raise IocError(
            f"{where}: {_clip(value)} looks like an attempt to say the removal time "
            "is unknown — write unquoted null instead (\"end\": null)"
        )
    if "T" not in text and " " not in text:
        raise IocError(
            f"{where}: {_clip(value)} has no time of day — write a full timestamp with "
            f"an offset, e.g. {text[:10]}T00:00:00+00:00 for the start of that day"
        )
    if not _HAS_SECONDS.search(text):
        if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}", text, re.ASCII):
            raise IocError(
                f"{where}: {_clip(value)} omits seconds — write them out (a missing second "
                "would silently become :00 and move the edge of the window)"
            )
        raise IocError(f"{where}: {_clip(value)} is not an ISO-8601 timestamp")
    if text.endswith("-00:00"):
        raise IocError(
            f"{where}: {_clip(value)} uses -00:00, which means 'offset unknown'; "
            "write +00:00 if the bound really is UTC"
        )
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError as e:
        # The exception embeds the whole value, so it is clipped too — this is the branch
        # a long mistyped bound actually reaches, and it was still emitting 100 kB.
        raise IocError(f"{where}: not an ISO-8601 timestamp ({_clip(e)})") from e
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise IocError(f"{where}: missing UTC offset in {_clip(value)}")
    return stamp


def _parse_bound_provenance(raw: object, where: str) -> BoundProvenance:
    _require(isinstance(raw, dict), f"{where}: must be an object")
    value = dict(raw)  # type: ignore[arg-type]
    _reject_unknown(value, _BOUND_PROVENANCE_KEYS, where)
    for key in ("kind", "source"):
        _require(key in value, f"{where}: missing {key!r}")
    _require(value["kind"] in PROVENANCE_VALUES,
             f"{where}.kind: must be one of {list(PROVENANCE_VALUES)}")
    _reject_placeholder(value["source"], f"{where}.source")
    _require(isinstance(value["source"], str) and _URL.fullmatch(value["source"]),
             f"{where}.source: must be one http(s) URL")
    return BoundProvenance(kind=value["kind"], source=value["source"])


def _parse_provenance(raw: object, where: str,
                      end: datetime | None) -> WindowProvenance:
    """Parse provenance and keep an unknown end coupled to a null bound."""
    _require(isinstance(raw, dict), f"{where}: must be an object")
    value = dict(raw)  # type: ignore[arg-type]
    _reject_unknown(value, _PROVENANCE_KEYS, where)
    for key in ("start", "end"):
        _require(key in value, f"{where}: missing {key!r}")
    start = _parse_bound_provenance(value["start"], f"{where}.start")
    end_origin = _parse_bound_provenance(value["end"], f"{where}.end")
    _require(start.kind != "unknown",
             f"{where}.start: a definite start cannot have unknown provenance")
    _require((end is None) == (end_origin.kind == "unknown"),
             f"{where}.end: use 'unknown' exactly when window.end is null")
    return WindowProvenance(start=start, end=end_origin)


def _parse_window(raw: object, where: str, now: datetime | None = None,
                  ) -> InstallableWindow:
    """One window. ``end: null`` means "not known to have stopped being installable"."""
    _require(isinstance(raw, dict), f"{where}: must be an object")
    window = dict(raw)  # type: ignore[arg-type]
    _reject_unknown(window, _WINDOW_KEYS, where)
    for key in ("start", "end"):
        _require(key in window, f"{where}: missing {key!r}")
    start = _parse_bound(window["start"], where=f"{where}.start")
    # Present but null: the feed says the right edge is unknown. Absent is still an
    # error — a missing key reads the same as a mistyped one.
    end = (None if window["end"] is None
           else _parse_bound(window["end"], where=f"{where}.end"))
    _require(end is None or start <= end, f"{where}: window start is after its end")
    # An advisory describes an incident that has already happened, so a start in the
    # future is a transcription error. Checked separately because `start <= end` used to
    # catch it for free and no longer does when the end is open: a mistyped year — 2025
    # for 2026, the likeliest slip at 3 a.m. — then produced a window containing nothing
    # that has happened yet, so every scan answered "no exposure found" and exited 0.
    now = now or datetime.now(timezone.utc)
    _require(start <= now + _CLOCK_SLACK,
             f"{where}.start: {start.isoformat()} is in the future — this host's clock "
             f"reads {now.isoformat()}. An advisory describes an incident that already "
             "happened, so check the year; if the date is right, check the clock")
    _require("provenance" in window, f"{where}: missing 'provenance'")
    provenance = _parse_provenance(window["provenance"], f"{where}.provenance", end)
    return InstallableWindow(start=start, end=end, provenance=provenance)


@dataclass(frozen=True)
class CompromisedPackage:
    """One package with the exact versions an advisory names as malicious."""

    name: str
    versions: tuple[str, ...]
    window: InstallableWindow | None  # overrides the advisory window
    sources: tuple[str, ...]
    notes: str | None = None


@dataclass(frozen=True)
class Advisory:
    """One incident, as published: window, compromised packages, provenance."""

    id: str
    name: str
    ecosystem: str
    window: InstallableWindow
    coverage: str
    packages: tuple[CompromisedPackage, ...]
    sources: tuple[str, ...]
    notes: str | None = None

    @property
    def is_partial(self) -> bool:
        return self.coverage == "partial"

    @property
    def coverage_warning(self) -> str | None:
        """Text a consumer must surface when a feed cannot prove absence."""
        if not self.is_partial:
            return None
        return (
            f"advisory {self.id} declares partial coverage: absence of exposure "
            "is not evidence of safety for packages this feed does not list"
        )

    def window_for(self, package: CompromisedPackage) -> InstallableWindow:
        """The effective window for one package entry."""
        if package.window is not None:
            return package.window
        return self.window

    def plan(self) -> QueryPlan:
        """The walker's work, with the coverage caveat and provenance attached.

        Consumers get a plan rather than a bare list of queries so that a
        ``partial`` feed cannot be scanned without its caveat travelling to the
        report: a list of queries would let "no exposure found" read as CLEAN
        for packages the feed never listed.
        """
        entries = []
        for pkg in self.packages:
            window = self.window_for(pkg)
            entries.append(PlannedQuery(
                query=WindowQuery(
                    package=pkg.name,
                    malicious_versions=frozenset(pkg.versions),
                    window_start=window.start,
                    window_end=window.end,
                ),
                package=pkg,
                window=window,
            ))
        return QueryPlan(
            advisory_id=self.id,
            advisory_name=self.name,
            coverage=self.coverage,
            coverage_warning=self.coverage_warning,
            sources=self.sources,
            entries=tuple(entries),
        )


@dataclass(frozen=True)
class PlannedQuery:
    """One walker query with the advisory entry it came from."""

    query: WindowQuery
    package: CompromisedPackage
    window: InstallableWindow

    @property
    def sources(self) -> tuple[str, ...]:
        return self.package.sources


@dataclass(frozen=True)
class QueryPlan:
    """Everything a scan needs from an advisory, caveat included."""

    advisory_id: str
    advisory_name: str
    coverage: str
    coverage_warning: str | None
    sources: tuple[str, ...]
    entries: tuple[PlannedQuery, ...]

    @property
    def queries(self) -> tuple[WindowQuery, ...]:
        return tuple(entry.query for entry in self.entries)

    @property
    def proves_absence(self) -> bool:
        """Whether 'nothing found' may be reported as CLEAN for this advisory."""
        return self.coverage_warning is None

    def __len__(self) -> int:
        return len(self.entries)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicated JSON keys instead of letting the last one win.

    A window block pasted twice would otherwise silently scan the wrong period.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise IocError(f"duplicate JSON key {key!r}: which one applies is ambiguous")
        seen.add(key)
    return dict(pairs)


def parse_advisory(text: str, now: datetime | None = None) -> Advisory:
    """Parse and validate advisory JSON. Every violation raises IocError.

    ``now`` is the clock the future-start check compares against. It exists so that check
    is testable without depending on the host's clock — this function is otherwise pure,
    and that check is the one thing in the module that is not.
    """
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError as e:
        raise IocError(f"not valid JSON: {e}") from e
    _require(isinstance(data, dict), "advisory root must be a JSON object")
    _reject_unknown(data, _ADVISORY_KEYS, "advisory")

    version = data.get("schema_version")
    _require(type(version) is int and version == SCHEMA_VERSION,
             f"advisory: schema_version must be the integer {SCHEMA_VERSION}, got {version!r}")
    for key in ("id", "name", "ecosystem", "coverage", "packages", "sources", "window"):
        _require(key in data, f"advisory: missing required field {key!r}")
    for key in ("id", "name", "ecosystem"):
        _required_str(data[key], f"advisory.{key}")
    _require(data["ecosystem"] == "npm",
             f"advisory.ecosystem: only 'npm' is supported, got {data['ecosystem']!r}")
    _require(data["coverage"] in COVERAGE_VALUES,
             f"advisory.coverage: must be one of {list(COVERAGE_VALUES)}")
    window = _parse_window(data["window"], "advisory.window", now)
    sources = _url_list(data["sources"], "advisory.sources")

    raw_packages = data["packages"]
    _require(isinstance(raw_packages, list) and raw_packages,
             "advisory.packages: must be a non-empty array")
    packages, seen = [], set()
    for i, raw in enumerate(raw_packages):
        where = f"advisory.packages[{i}]"
        _require(isinstance(raw, dict), f"{where}: must be an object")
        _reject_unknown(raw, _PACKAGE_KEYS, where)
        for key in ("name", "versions", "sources"):
            _require(key in raw, f"{where}: missing required field {key!r}")
        name = _package_name(raw["name"], f"{where}.name")
        versions = _versions(raw["versions"], f"{where}.versions")
        pkg_window = (_parse_window(raw["window"], f"{where}.window", now)
                      if "window" in raw else None)
        if pkg_window is not None:
            _require(window.start <= pkg_window.start
                     and _closes_within(pkg_window.end, window.end),
                     f"{where}.window: {_fmt_window(pkg_window)} is not inside the advisory "
                     f"window {_fmt_window(window)}; widen the advisory window instead")
        # A package may appear twice only for genuinely different waves, so each
        # repeat must carry its own window; otherwise it is a paste error.
        # Provenance explains a window; it does not make identical bounds a second
        # incident wave. Keep the duplicate rule on the interval itself.
        key = (name, None if pkg_window is None
               else (pkg_window.start, pkg_window.end))
        _require(key not in seen,
                 f"{where}.name: duplicate entry for {name!r} with the same window "
                 "(give each wave its own 'window' if this is intentional)")
        seen.add(key)
        packages.append(CompromisedPackage(
            name=name,
            versions=versions,
            window=pkg_window,
            sources=_url_list(raw["sources"], f"{where}.sources"),
            notes=_optional_str(raw.get("notes"), f"{where}.notes"),
        ))

    return Advisory(
        id=data["id"], name=data["name"], ecosystem=data["ecosystem"],
        window=window, coverage=data["coverage"], packages=tuple(packages),
        sources=sources, notes=_optional_str(data.get("notes"), "advisory.notes"),
    )


def _closes_within(inner: datetime | None, outer: datetime | None) -> bool:
    """Whether one window's end stays inside another's.

    An open end is the *latest* possible end, so it fits inside another open end and
    inside nothing else: a package window that never closes cannot sit inside an
    advisory window that does, because it would claim exposure past the advisory's
    own edge.
    """
    if outer is None:
        return True
    return inner is not None and inner <= outer


def _fmt_window(window: InstallableWindow) -> str:
    end = "open" if window.end is None else window.end.isoformat()
    return f"[{window.start.isoformat()} .. {end}]"


def _package_name(raw: object, where: str) -> str:
    """An npm package name exactly as a lockfile would spell it.

    Names are matched against lockfile entries by equality, so a stray space or
    a ``name@version`` cell copied out of a vendor table would match nothing and
    read as CLEAN. Anything that cannot be an npm name is an error, not a scan.
    """
    _require(isinstance(raw, str), f"{where}: must be a string")
    name = str(raw).strip()
    _require(name != "", f"{where}: must not be empty")
    _require(len(name) <= _NPM_NAME_MAX,
             f"{where}: npm names are at most {_NPM_NAME_MAX} characters")
    _require(name.lower() not in _NPM_NAME_RESERVED,
             f"{where}: {name!r} is a name npm reserves and no package can have "
             "(a column header copied out of a table?)")
    if not _NPM_NAME.fullmatch(name):
        hint = ""
        if "@" in name[1:]:
            hint = " — looks like 'name@version'; put the version in 'versions'"
        elif name != name.lower():
            hint = " — npm names are lowercase"
        elif any(c.isspace() for c in name):
            hint = " — contains whitespace"
        raise IocError(f"{where}: {raw!r} is not a valid npm package name{hint}")
    return name


def _versions(raw: object, where: str) -> tuple[str, ...]:
    """Exact resolved versions only.

    A lockfile records one resolved version per install, so a range or dist-tag
    could never match it: accepting ``^5.6.1`` would silently judge nothing and
    report CLEAN. Ranges are rejected rather than expanded, because expanding
    one would judge versions the advisory never named.
    """
    versions = _string_list(raw, where, required=True)
    _require(len(set(versions)) == len(versions), f"{where}: duplicate versions")
    for version in versions:
        if not _SEMVER.fullmatch(version):
            hint = " — ranges and tags cannot match a resolved lockfile version"
            if version.startswith(("v", "V")):
                hint = " — drop the leading 'v'"
            elif not version.isascii():
                hint = " — contains non-ASCII digits or characters"
            elif version.count(".") < 2:
                hint = " — npm versions have three parts (major.minor.patch)"
            raise IocError(f"{where}: {version!r} is not an exact SemVer version{hint}")
    return versions


def _url_list(raw: object, where: str) -> tuple[str, ...]:
    """Provenance is an invariant: every entry must be a resolvable http(s) URL."""
    items = _string_list(raw, where, required=True)
    for item in items:
        _require(bool(_URL.fullmatch(item)),
                 f"{where}: {item!r} is not an http(s) URL; every entry needs a source "
                 "a reader can open")
    return items


def _string_list(raw: object, where: str, *, required: bool) -> tuple[str, ...]:
    _require(isinstance(raw, list), f"{where}: must be an array")
    items = list(raw)  # type: ignore[arg-type]
    _require(not required or items, f"{where}: must not be empty")
    for item in items:
        _require(isinstance(item, str) and item.strip(),
                 f"{where}: entries must be non-empty strings")
    return tuple(str(i).strip() for i in items)


def _required_str(raw: object, where: str) -> str:
    """A non-empty string that is not the template's marker."""
    _require(isinstance(raw, str) and str(raw).strip() != "",
             f"{where}: must be a non-empty string")
    _reject_placeholder(raw, where)
    return str(raw).strip()


def _optional_str(raw: object, where: str) -> str | None:
    if raw is None:
        return None
    _require(isinstance(raw, str), f"{where}: must be a string")
    return str(raw)


def load_advisory(path: str | Path) -> Advisory:
    """Load an advisory from a file path, or by bundled feed name (no .json)."""
    text_path = str(path)
    looks_like_path = ("/" in text_path or "\\" in text_path
                       or text_path.endswith(".json") or Path(text_path).exists())
    if looks_like_path:
        candidate = Path(text_path)
        if not candidate.is_file():
            raise IocError(f"advisory not found: {text_path!r}")
    else:
        candidate = FEEDS_DIR / f"{text_path}.json"
        if not candidate.is_file():
            raise IocError(
                f"no bundled feed named {text_path!r} "
                f"(available: {', '.join(bundled_feeds())})"
            )
    try:
        text = candidate.read_text(encoding="utf-8")
    except OSError as e:
        raise IocError(f"cannot read advisory {candidate}: {e}") from e
    return parse_advisory(text)


def bundled_feeds() -> list[str]:
    return sorted(p.stem for p in FEEDS_DIR.glob("*.json"))


# What the window means, said in the file itself. JSON has no comments, and this is the
# field that decides every verdict: vendors headline the interval the *attacker* was
# active, which is not the interval the malicious artifact was *installable*. Enter the
# first and every scan returns CLEAN — the failure this tool exists to prevent.
WINDOW_NOTE = (
    "window is the interval the malicious artifact was INSTALLABLE — first malicious "
    "publish to registry removal — not the interval the attacker was active. The two "
    "differ, and using the second makes every scan report CLEAN. 'end': null means the "
    "removal time is unknown, which is the usual case: no registry records it. Leave it "
    "null rather than guessing — a wide window over-reports, a narrow one hides. "
    "See docs/ioc-format.md."
)

TEMPLATE_HINTS = {
    "id": "the advisory's own identifier, e.g. GHSA-xxxx-xxxx-xxxx or MAL-0000-1234",
    "name": "one line a responder will recognise months later",
    "coverage": "'complete' if this file lists every affected package of the incident, "
                "'partial' if not — a partial feed can never prove absence",
    "sources": "where each claim came from; a verdict is only as good as its advisory",
    "end": "the last instant it was installable, or pass --end-unknown to write null — "
           "no registry records a removal, so null is usually the honest answer",
}


def advisory_template(*, package: str | None = None, versions: tuple[str, ...] = (),
                      start: str | None = None, end: str | None = None,
                      end_unknown: bool = False,
                      source: str | None = None, identifier: str | None = None,
                      name: str | None = None) -> str:
    """An advisory to edit, or a complete one when every fact is already known.

    A fully-specified call produces a file that validates. Anything left out is written
    as ``REPLACE-ME``, which fails validation on purpose: an advisory with no source has
    no provenance, and a verdict is only ever as good as the advisory behind it. That is
    why ``coverage`` defaults to ``partial`` too — claiming a feed lists every affected
    package of an incident is a claim, and the default should not make it silently.
    """
    body = {
        "schema_version": SCHEMA_VERSION,
        # Never derived from the package. There have been several chalk incidents, and
        # naming them all LOCAL-CHALK-0001 would make two different events indexable as
        # one — the report keys its whole verdict on this field.
        "id": identifier or f"{PLACEHOLDER}: {TEMPLATE_HINTS['id']}",
        "name": name or f"{PLACEHOLDER}: {TEMPLATE_HINTS['name']}",
        "ecosystem": "npm",
        "coverage": "partial",
        "window": {
            "start": start or f"{PLACEHOLDER}: 2025-11-24T00:00:00+00:00",
            # `null` only when the caller *said* the end is unknown. Silence is not that
            # statement: inferring "unknown" from "flag not passed" is the one thing this
            # module refuses to do anywhere else, and it would turn a forgotten flag into
            # a window that never closes. Without either, the blank stands and the
            # template fails validation by name, as every other blank does.
            "end": None if end_unknown else (end or f"{PLACEHOLDER}: {TEMPLATE_HINTS['end']}"),
            "provenance": {
                "start": {
                    "kind": "operator-supplied",
                    "source": source or f"{PLACEHOLDER}: https://...",
                },
                "end": {
                    "kind": "unknown" if end_unknown else "operator-supplied",
                    "source": source or f"{PLACEHOLDER}: https://...",
                },
            },
        },
        "packages": [{
            "name": package or PLACEHOLDER,
            "versions": list(versions) or [PLACEHOLDER],
            "sources": [source or f"{PLACEHOLDER}: https://..."],
        }],
        "sources": [source or f"{PLACEHOLDER}: https://..."],
        "notes": WINDOW_NOTE,
    }
    return json.dumps(body, indent=2, ensure_ascii=False) + "\n"
