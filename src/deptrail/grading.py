"""Grade an exposure by how strongly the evidence says the malicious code ran.

A lockfile pinning a compromised version proves the pin, not the install. What a
responder needs to decide is narrower: *did an install actually happen while the
artifact was live, and therefore must these secrets be rotated?* CI run records
answer that where they exist, and this module states exactly how far each answer
reaches:

- ``CONFIRMED``  — a CI run checked out the exposing commit and started inside
  the window: an install ran against a lockfile pinning the malicious version.
- ``LIKELY``     — CI activity coincides with the exposure, but not on the
  exposing commit itself, or the run on that commit started outside the window.
- ``POSSIBLE``   — the pin overlapped the window and nothing rules an install
  in or out. Developer machines leave no run records at all, so this is the
  honest grade for "no CI evidence", never a downgrade to safe.
- ``NO_EVIDENCE``— no exposure interval overlapped the window.

Two failure modes are deliberately designed against. Run records expire (GitHub
keeps them ~90 days by default), so a window older than the retention horizon
must not read as "no install happened" — it produces POSSIBLE plus a warning
that the records are gone. And a workflow whose steps never install dependencies
cannot confirm anything, but it also cannot clear the repo, because the developer
who committed the lockfile ran the install locally.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from .history import Exposure, RepoFinding, Verdict, WindowQuery, _parse_iso

# Workflow steps that fetch dependencies; a run containing one of these executed
# whatever the lockfile pinned, including any install scripts it carried.
INSTALL_HINTS = ("npm ci", "npm install", "npm i ", "yarn install", "pnpm install",
                 "setup-node", "actions/setup-node")


class Grade(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    NO_EVIDENCE = "NO_EVIDENCE"


@dataclass(frozen=True)
class RunRecord:
    """One CI run, reduced to what grading needs."""

    run_id: str
    head_sha: str
    started_at: datetime
    workflow: str
    installs_dependencies: bool | None = None  # None = could not tell


@dataclass(frozen=True)
class RunHistory:
    """The run records available for a repo, and how far back they reach.

    ``oldest_available`` is the horizon of what the source could see. A window
    that starts before it is simply unanswered — the distinction between
    "no install" and "records expired" is the whole point of carrying it.
    """

    records: tuple[RunRecord, ...] = ()
    oldest_available: datetime | None = None
    source: str = "unknown"

    def covers(self, moment: datetime) -> bool:
        if self.oldest_available is None:
            return False
        return moment >= self.oldest_available


@dataclass(frozen=True)
class GradedExposure:
    """One exposure with its grade and the facts the grade rests on."""

    exposure: Exposure
    grade: Grade
    evidence: tuple[str, ...]
    run_ids: tuple[str, ...] = ()


@dataclass
class GradedFinding:
    """A repo's exposures, graded, plus anything that limited the grading."""

    repo: Path
    verdict: Verdict
    graded: list[GradedExposure] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def worst_grade(self) -> Grade:
        for grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE):
            if any(g.grade is grade for g in self.graded):
                return grade
        return Grade.NO_EVIDENCE

    @property
    def needs_rotation(self) -> bool:
        """Whether this repo belongs on the rotation checklist.

        POSSIBLE counts: an unprovable install is not an absent one, and the
        cost of rotating one extra credential is smaller than the cost of
        leaving a live one in an attacker's hands.
        """
        return self.worst_grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE)


def _overlap(exposure: Exposure, query: WindowQuery) -> tuple[datetime, datetime]:
    """The instants when the pin and the window coincide — where an install counts."""
    start = max(exposure.since, query.window_start)
    end = query.window_end if exposure.until is None else min(exposure.until, query.window_end)
    return start, end


def grade_exposure(exposure: Exposure, query: WindowQuery,
                   history: RunHistory) -> GradedExposure:
    """Grade one exposure against the run records. Pure: no I/O, no clock."""
    start, end = _overlap(exposure, query)
    in_window = [r for r in history.records if start <= r.started_at <= end]
    on_commit = [r for r in history.records if r.head_sha == exposure.commit]
    installing = [r for r in in_window
                  if r.head_sha == exposure.commit and r.installs_dependencies is not False]

    if installing:
        run = installing[0]
        return GradedExposure(
            exposure=exposure, grade=Grade.CONFIRMED,
            evidence=(
                f"run {run.run_id} ({run.workflow}) checked out {exposure.commit[:8]} "
                f"at {run.started_at.isoformat()}, inside the window",
                f"that commit pinned {exposure.version} in {exposure.lockfile_path}",
            ),
            run_ids=tuple(r.run_id for r in installing),
        )

    if on_commit:
        run = on_commit[0]
        return GradedExposure(
            exposure=exposure, grade=Grade.LIKELY,
            evidence=(
                f"run {run.run_id} checked out the exposing commit "
                f"{exposure.commit[:8]} but started {run.started_at.isoformat()}, "
                f"outside the interval when {exposure.version} was both pinned and "
                f"live ({start.isoformat()} .. {end.isoformat()}); the install may "
                "have failed after removal",
            ),
            run_ids=tuple(r.run_id for r in on_commit),
        )

    if in_window:
        return GradedExposure(
            exposure=exposure, grade=Grade.LIKELY,
            evidence=(
                f"{len(in_window)} CI run(s) started while {exposure.version} was "
                "pinned and live, on other commits",
            ),
            run_ids=tuple(r.run_id for r in in_window),
        )

    if not history.covers(start):
        return GradedExposure(
            exposure=exposure, grade=Grade.POSSIBLE,
            evidence=(
                f"no CI records reach back to {start.isoformat()} "
                f"(source: {history.source}); an install cannot be ruled out",
            ),
        )

    return GradedExposure(
        exposure=exposure, grade=Grade.POSSIBLE,
        evidence=(
            "no CI run coincides with the exposure; a developer machine install "
            "leaves no record, so this cannot be cleared",
        ),
    )


def grade_finding(finding: RepoFinding, query: WindowQuery,
                  history: RunHistory) -> GradedFinding:
    """Grade every exposure in a repo finding, carrying its warnings forward."""
    graded = GradedFinding(
        repo=finding.repo, verdict=finding.verdict, warnings=list(finding.warnings)
    )
    for exposure in finding.exposures:
        graded.graded.append(grade_exposure(exposure, query, history))
    for item in graded.graded:
        start, _ = _overlap(item.exposure, query)
        if item.grade is Grade.POSSIBLE and not history.covers(start):
            graded.warnings.append(
                f"CI records do not reach {start.isoformat()}: "
                "absence of a run is not absence of an install"
            )
            break
    return graded


def runs_from_github(repo_slug: str, *, limit: int = 200) -> RunHistory:
    """Read run records through the GitHub CLI.

    Only run metadata is used — never logs — because logs expire long before the
    runs they belong to, and metadata is enough to place an install in time.
    """
    try:
        raw = subprocess.run(
            ["gh", "run", "list", "--repo", repo_slug, "--limit", str(limit),
             "--json", "databaseId,headSha,startedAt,name"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise RuntimeError(f"could not read CI runs for {repo_slug}: {e}") from e
    records = []
    for item in json.loads(raw or "[]"):
        records.append(RunRecord(
            run_id=str(item["databaseId"]),
            head_sha=item["headSha"],
            started_at=_parse_iso(item["startedAt"]),
            workflow=item.get("name") or "unknown",
        ))
    records.sort(key=lambda r: r.started_at)
    return RunHistory(
        records=tuple(records),
        # The oldest record we actually saw is the only horizon we can claim; a
        # full page means older runs may exist beyond it, so we stay silent.
        oldest_available=records[0].started_at if records and len(records) < limit else None,
        source=f"gh run list --repo {repo_slug}",
    )
