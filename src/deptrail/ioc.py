"""Advisory (IOC) input format: what a vendor publishes, in a form the walker can judge.

Two hard rules shape this module, both learned from the walker's review:

- **Nothing is inferred.** No default window, no guessed timezone, no version
  ranges. A hand-transcribed feed with a typo'd key fails loudly rather than
  scanning for the wrong thing; every unknown key is an error, not a shrug.
- **Coverage is part of the evidence.** Advisories are published incrementally,
  so a feed declares whether its package list is ``complete`` or ``partial``.
  A partial feed can prove exposure but can never prove its absence, and
  consumers must surface that (see ``Advisory.coverage_warning``).

Windows are inclusive on both ends and must be written as full ISO-8601
timestamps with a UTC offset — no bare dates, because deciding which instants a
published date covers is a judgment that belongs in the feed, visible to whoever
reads the report.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .history import WindowQuery

FEEDS_DIR = Path(__file__).parent / "feeds"
SCHEMA_VERSION = 1
COVERAGE_VALUES = ("complete", "partial")

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
    _require(isinstance(raw, dict), f"{where}: window must be an object")
    window = dict(raw)  # type: ignore[arg-type]
    _reject_unknown(window, _WINDOW_KEYS, where)
    for key in _WINDOW_KEYS:
        _require(key in window, f"{where}: window is missing {key!r}")
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


def parse_advisory(text: str) -> Advisory:
    """Parse and validate advisory JSON. Every violation raises IocError."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise IocError(f"not valid JSON: {e}") from e
    _require(isinstance(data, dict), "advisory root must be a JSON object")
    _reject_unknown(data, _ADVISORY_KEYS, "advisory")

    version = data.get("schema_version")
    _require(version == SCHEMA_VERSION,
             f"advisory: schema_version must be {SCHEMA_VERSION}, got {version!r}")
    for key in ("id", "name", "ecosystem", "coverage", "packages", "sources", "window"):
        _require(key in data, f"advisory: missing required field {key!r}")
    for key in ("id", "name", "ecosystem"):
        _require(isinstance(data[key], str) and data[key].strip(),
                 f"advisory.{key}: must be a non-empty string")
    _require(data["ecosystem"] == "npm",
             f"advisory.ecosystem: only 'npm' is supported, got {data['ecosystem']!r}")
    _require(data["coverage"] in COVERAGE_VALUES,
             f"advisory.coverage: must be one of {list(COVERAGE_VALUES)}")
    window = _parse_window(data["window"], "advisory")
    sources = _string_list(data["sources"], "advisory.sources", required=True)

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
        name = raw["name"]
        _require(isinstance(name, str) and name.strip(), f"{where}.name: must be a non-empty string")
        _require(name not in seen, f"{where}.name: duplicate entry for {name!r}")
        seen.add(name)
        versions = _string_list(raw["versions"], f"{where}.versions", required=True)
        _require(len(set(versions)) == len(versions), f"{where}.versions: duplicate versions")
        packages.append(CompromisedPackage(
            name=name,
            versions=versions,
            window=_parse_window(raw["window"], where) if "window" in raw else None,
            sources=_string_list(raw["sources"], f"{where}.sources", required=True),
            notes=_optional_str(raw.get("notes"), f"{where}.notes"),
        ))

    return Advisory(
        id=data["id"], name=data["name"], ecosystem=data["ecosystem"],
        window=window, coverage=data["coverage"], packages=tuple(packages),
        sources=sources, notes=_optional_str(data.get("notes"), "advisory.notes"),
    )


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
    candidate = Path(path)
    if not candidate.exists():
        bundled = FEEDS_DIR / f"{candidate.name}.json"
        if bundled.exists():
            candidate = bundled
        else:
            raise IocError(
                f"advisory not found: {path!r} (bundled feeds: {', '.join(bundled_feeds())})"
            )
    try:
        text = candidate.read_text(encoding="utf-8")
    except OSError as e:
        raise IocError(f"cannot read advisory {candidate}: {e}") from e
    return parse_advisory(text)


def bundled_feeds() -> list[str]:
    return sorted(p.stem for p in FEEDS_DIR.glob("*.json"))
