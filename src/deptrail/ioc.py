"""Advisory (IOC) input format: what a vendor publishes, in a form the walker can judge.

Two hard rules shape this module, both learned from the walker's review:

- **Nothing is inferred.** No default window, no guessed timezone, no version
  ranges. A hand-transcribed feed with a typo'd key fails loudly rather than
  scanning for the wrong thing; every unknown key is an error, not a shrug.
- **Coverage is part of the evidence.** Advisories are published incrementally,
  so a feed declares whether its package list is ``complete`` or ``partial``.
  A partial feed can prove exposure but can never prove its absence, and
  consumers must surface that (see ``Advisory.coverage_warning``).

A window is the interval in which the malicious artifact was **installable** —
first malicious publish until the registry removed it — not the interval in which
the attacker was active. Vendors usually publish the latter, and the two differ
by hours: the TanStack wave's CI compromise ran 11:29-19:15 UTC while the
poisoned versions only appeared at 19:20 and later, so a feed transcribing the
attacker-activity window could only ever return CLEAN. When the removal time is
not published, a deliberately late end bound is the safe error: a wide window
over-reports exposure, a narrow one hides it.

Windows are inclusive on both ends and must be written as full ISO-8601
timestamps with a UTC offset — no bare dates, because deciding which instants a
published date covers is a judgment that belongs in the feed, visible to whoever
reads the report.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .history import WindowQuery

FEEDS_DIR = Path(__file__).parent / "feeds"
SCHEMA_VERSION = 1
COVERAGE_VALUES = ("complete", "partial")

# npm's own name rule (lowercase since 2014), and an exact-version shape: a
# lockfile stores a resolved version string, so anything a range or tag could
# expand to would match nothing and read as CLEAN.
_NPM_NAME = re.compile(r"^(?:@[a-z0-9-~][a-z0-9._~-]*/)?[a-z0-9-~][a-z0-9._~-]*$")
_EXACT_VERSION = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.+-]+)?$")
_URL = re.compile(r"^https?://\S+$")

_ADVISORY_KEYS = {
    "schema_version", "id", "name", "ecosystem", "window", "coverage",
    "packages", "sources", "notes",
}
_PACKAGE_KEYS = {"name", "versions", "window", "sources", "notes"}
_WINDOW_KEYS = {"start", "end"}


class IocError(ValueError):
    """The advisory input is malformed. Never raised for merely surprising data."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IocError(message)


def _reject_unknown(obj: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(obj) - allowed)
    _require(not unknown, f"{where}: unknown field(s) {unknown}; allowed {sorted(allowed)}")


def _parse_bound(value: object, *, where: str) -> datetime:
    """Parse one window bound: a full ISO-8601 timestamp with a UTC offset.

    Nothing is widened or defaulted. A bare date is rejected rather than turned
    into midnight in a timezone we picked — if a vendor publishes only a date,
    the person transcribing it decides which instants the day covers, and that
    decision belongs in the feed where a reader can see it.
    """
    _require(isinstance(value, str) and str(value).strip() != "",
             f"{where}: must be a non-empty string")
    text = str(value).strip().replace("Z", "+00:00")
    if "T" not in text and " " not in text:
        raise IocError(
            f"{where}: {value!r} has no time of day — write a full timestamp with "
            f"an offset, e.g. {text[:10]}T00:00:00+00:00 for the start of that day"
        )
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError as e:
        raise IocError(f"{where}: not an ISO-8601 timestamp ({e})") from e
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise IocError(f"{where}: missing UTC offset in {value!r}")
    return stamp


def _parse_window(raw: object, where: str) -> tuple[datetime, datetime]:
    _require(isinstance(raw, dict), f"{where}: must be an object")
    window = dict(raw)  # type: ignore[arg-type]
    _reject_unknown(window, _WINDOW_KEYS, where)
    for key in _WINDOW_KEYS:
        _require(key in window, f"{where}: missing {key!r}")
    start = _parse_bound(window["start"], where=f"{where}.start")
    end = _parse_bound(window["end"], where=f"{where}.end")
    _require(start <= end, f"{where}: window start is after its end")
    return start, end


@dataclass(frozen=True)
class CompromisedPackage:
    """One package with the exact versions an advisory names as malicious."""

    name: str
    versions: tuple[str, ...]
    window: tuple[datetime, datetime] | None  # overrides the advisory window
    sources: tuple[str, ...]
    notes: str | None = None


@dataclass(frozen=True)
class Advisory:
    """One incident, as published: window, compromised packages, provenance."""

    id: str
    name: str
    ecosystem: str
    window: tuple[datetime, datetime]
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

    def queries(self) -> list[WindowQuery]:
        """One WindowQuery per package — the walker's unit of work."""
        return [
            WindowQuery(
                package=pkg.name,
                malicious_versions=frozenset(pkg.versions),
                window_start=(pkg.window or self.window)[0],
                window_end=(pkg.window or self.window)[1],
            )
            for pkg in self.packages
        ]


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


def parse_advisory(text: str) -> Advisory:
    """Parse and validate advisory JSON. Every violation raises IocError."""
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
        _require(isinstance(data[key], str) and data[key].strip(),
                 f"advisory.{key}: must be a non-empty string")
    _require(data["ecosystem"] == "npm",
             f"advisory.ecosystem: only 'npm' is supported, got {data['ecosystem']!r}")
    _require(data["coverage"] in COVERAGE_VALUES,
             f"advisory.coverage: must be one of {list(COVERAGE_VALUES)}")
    window = _parse_window(data["window"], "advisory.window")
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
        pkg_window = _parse_window(raw["window"], f"{where}.window") if "window" in raw else None
        if pkg_window is not None:
            _require(window[0] <= pkg_window[0] and pkg_window[1] <= window[1],
                     f"{where}.window: {_fmt_window(pkg_window)} is not inside the advisory "
                     f"window {_fmt_window(window)}; widen the advisory window instead")
        # A package may appear twice only for genuinely different waves, so each
        # repeat must carry its own window; otherwise it is a paste error.
        key = (name, pkg_window)
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


def _fmt_window(window: tuple[datetime, datetime]) -> str:
    return f"[{window[0].isoformat()} .. {window[1].isoformat()}]"


def _package_name(raw: object, where: str) -> str:
    """An npm package name exactly as a lockfile would spell it.

    Names are matched against lockfile entries by equality, so a stray space or
    a ``name@version`` cell copied out of a vendor table would match nothing and
    read as CLEAN. Anything that cannot be an npm name is an error, not a scan.
    """
    _require(isinstance(raw, str), f"{where}: must be a string")
    name = str(raw).strip()
    _require(name != "", f"{where}: must not be empty")
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
        if not _EXACT_VERSION.fullmatch(version):
            hint = " — ranges and tags cannot match a resolved lockfile version"
            if version.startswith(("v", "V")):
                hint = " — drop the leading 'v'"
            raise IocError(f"{where}: {version!r} is not an exact version{hint}")
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
