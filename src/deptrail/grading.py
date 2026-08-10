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

``CONFIRMED`` demands positive evidence on both axes: the run must be shown to
have installed dependencies (its steps are inspected), and it must have started
while the artifact was live. A run we cannot inspect, or one that ran before the
version turned malicious, does not confirm anything.

Three failure modes are deliberately designed against. Run records expire
(GitHub keeps them ~90 days by default), so a window older than the retention
horizon must not read as "no install happened" — it produces POSSIBLE plus a
warning that the records are gone. A repository whose history could not be read
at all (shallow clone, unreadable snapshot) is likewise POSSIBLE, never
NO_EVIDENCE: nothing was ruled out, so nothing may be cleared. And a workflow
whose steps never install dependencies cannot confirm anything, but it also
cannot clear the repo, because the developer who committed the lockfile ran the
install locally.

Known limits of the run metadata: for ``pull_request`` events the run checks out
an ephemeral merge of head and base, so its install reflects that merge rather
than the head snapshot alone; and ``startedAt`` is rewritten by re-runs, so the
earlier of ``createdAt``/``startedAt`` is used as a run's effective time.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from .history import (
    Exposure,
    GitError,
    RepoFinding,
    Verdict,
    WindowQuery,
    _git as _git_text,
    _parse_iso,
)

# Workflow steps that fetch dependencies; a run containing one of these executed
# whatever the lockfile pinned, including any install scripts it carried.
# Commands that unambiguously install this ecosystem's dependencies. Only these
# can raise a grade to CONFIRMED: a step merely named "Install" may be
# installing anything, and guessing would assert an execution that never
# happened (measured against real workflows — see docs/experiments.md).
INSTALL_COMMANDS = ("npm ci", "npm i ", "npm install", "yarn install", "yarn --frozen",
                    "pnpm install", "pnpm i ", "npm-run-all install")
# GitHub's default run retention; used only to say "the records for that window
# are probably gone", never to claim a run did or did not happen.
RETENTION = timedelta(days=90)


class Grade(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    NO_EVIDENCE = "NO_EVIDENCE"


@dataclass(frozen=True)
class RunRecord:
    """One CI run, reduced to what grading needs.

    ``created_at`` is kept because a re-run rewrites ``startedAt``: the earlier
    of the two is the run's effective time, so a re-run months later cannot move
    an install out of the window it actually happened in.
    """

    run_id: str
    head_sha: str
    started_at: datetime
    workflow: str
    installs_dependencies: bool | None = None  # None = could not tell
    workflow_path: str | None = None  # the file that defines this run
    created_at: datetime | None = None
    event: str = "unknown"
    attempt: int = 1

    @property
    def at(self) -> datetime:
        return min(self.started_at, self.created_at or self.started_at)


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
    """A repo's exposures, graded, plus anything that limited the grading.

    The advisory identity and its coverage caveat travel with the grades so a
    report cannot show "nothing found" for a partial feed without the caveat.
    """

    repo: Path
    verdict: Verdict
    graded: list[GradedExposure] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    advisory_id: str | None = None
    package: str | None = None
    coverage_warning: str | None = None

    @property
    def worst_grade(self) -> Grade:
        for grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE):
            if any(g.grade is grade for g in self.graded):
                return grade
        if self.verdict is Verdict.INDETERMINATE:
            # The walker could not read this repo's history, so an install was
            # neither shown nor ruled out — which is what POSSIBLE means.
            # NO_EVIDENCE would claim the lockfile never held a named version.
            return Grade.POSSIBLE
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


# Events whose run checks out the head commit itself. A ``pull_request`` run
# checks out an ephemeral merge of head and base instead, so what it installed is
# that merge — it can support a grade but never confirm one for this commit.
HEAD_CHECKOUT_EVENTS = ("push", "workflow_dispatch", "schedule", "release")


def grade_exposure(exposure: Exposure, query: WindowQuery,
                   history: RunHistory) -> GradedExposure:
    """Grade one exposure against the run records. Pure: no I/O, no clock.

    Only runs that built *this* commit are evidence. A run on some other commit
    installed a different lockfile state, so it says nothing about this exposure
    — counting it would inflate the incident. The window, not the pin's end,
    bounds what such a run could have fetched: checking out an old commit after
    the fix still pulls the malicious artifact while the registry serves it.
    """
    live_start = max(exposure.since, query.window_start)
    on_commit = [r for r in history.records if r.head_sha == exposure.commit]
    during = [r for r in on_commit if live_start <= r.at <= query.window_end]
    confirming = [r for r in during
                  if r.installs_dependencies is True
                  and r.event in HEAD_CHECKOUT_EVENTS]

    if confirming:
        run = confirming[0]
        return GradedExposure(
            exposure=exposure, grade=Grade.CONFIRMED,
            evidence=(
                f"run {run.run_id} ({run.workflow}, {run.event}) built "
                f"{exposure.commit[:8]} at {run.at.isoformat()}, while "
                f"{exposure.version} was still served by the registry",
                f"the workflows at that commit install dependencies, so "
                f"{exposure.version} executed",
            ),
            run_ids=tuple(r.run_id for r in confirming),
        )

    if during:
        run = during[0]
        if run.event == "pull_request":
            why = ("a pull_request run installs a merge of head and base, not "
                   "this commit's tree")
        elif run.installs_dependencies is False:
            why = "the workflows at that commit install no dependencies"
        else:
            why = "the workflows at that commit could not be read"
        return GradedExposure(
            exposure=exposure, grade=Grade.LIKELY,
            evidence=(
                f"run {run.run_id} ({run.workflow}, {run.event}) built "
                f"{exposure.commit[:8]} at {run.at.isoformat()}, while "
                f"{exposure.version} was still served, but {why}",
            ),
            run_ids=tuple(r.run_id for r in during),
        )

    later = [r for r in on_commit if r.at > query.window_end]
    if later:
        run = later[0]
        return GradedExposure(
            exposure=exposure, grade=Grade.LIKELY,
            evidence=(
                f"run {run.run_id} built the exposing commit "
                f"{exposure.commit[:8]} at {run.at.isoformat()}, after "
                f"{query.window_end.isoformat()} when {exposure.version} was no "
                "longer served; the install may have failed rather than fetched it",
            ),
            run_ids=tuple(r.run_id for r in later),
        )

    if not history.covers(live_start):
        return GradedExposure(
            exposure=exposure, grade=Grade.POSSIBLE,
            evidence=(
                f"no CI records reach back to {live_start.isoformat()} "
                f"(source: {history.source}); an install cannot be ruled out",
            ),
        )

    return GradedExposure(
        exposure=exposure, grade=Grade.POSSIBLE,
        evidence=(
            f"no CI run built {exposure.commit[:8]} while {exposure.version} was "
            "served; a developer machine install leaves no record, so this cannot "
            "be cleared",
        ),
    )


def grade_finding(finding: RepoFinding, query: WindowQuery, history: RunHistory,
                  *, advisory_id: str | None = None,
                  coverage_warning: str | None = None) -> GradedFinding:
    """Grade every exposure in a repo finding, carrying its caveats forward."""
    graded = GradedFinding(
        repo=finding.repo, verdict=finding.verdict, warnings=list(finding.warnings),
        advisory_id=advisory_id, package=query.package,
        coverage_warning=coverage_warning,
    )
    graded.graded.extend(grade_exposure(e, query, history) for e in finding.exposures)

    if finding.exposures:
        earliest = min(_overlap(e, query)[0] for e in finding.exposures)
        newest = max((r.at for r in history.records), default=None)
        beyond_retention = newest is not None and earliest < newest - RETENTION
        if not history.covers(earliest) or beyond_retention:
            graded.warnings.append(
                f"CI records may not reach {earliest.isoformat()} "
                f"(GitHub keeps runs ~{RETENTION.days} days): absence of a run is "
                "not absence of an install"
            )
    return graded


def parse_run_list(raw: str, *, source: str,
                   covered_from: datetime | None = None) -> RunHistory:
    """Turn the API's run list into records. Pure, so it can be tested directly.

    Runs without a usable start time (queued, or serialised as a zero date) are
    dropped: a record that cannot be placed in time must not silently claim a
    retention horizon it does not establish.
    """
    payload = json.loads(raw or "{}")
    items = payload.get("workflow_runs", payload) if isinstance(payload, dict) else payload
    records, skipped = [], 0
    for item in items or ():
        stamp = item.get("run_started_at") or item.get("created_at")
        created = item.get("created_at")
        if not stamp or str(stamp).startswith("0001"):
            skipped += 1
            continue
        records.append(RunRecord(
            run_id=str(item.get("id") or item.get("databaseId")),
            head_sha=item["head_sha"] if "head_sha" in item else item["headSha"],
            started_at=_parse_iso(stamp),
            created_at=_parse_iso(created) if created and not str(created).startswith("0001") else None,
            workflow=item.get("name") or "unknown",
            workflow_path=item.get("path"),
            event=item.get("event") or "unknown",
            attempt=int(item.get("run_attempt") or 1),
        ))
    records.sort(key=lambda r: r.at)
    note = f"{source} ({skipped} run(s) without a start time skipped)" if skipped else source
    return RunHistory(records=tuple(records), oldest_available=covered_from, source=note)


def runs_from_github(repo_slug: str, *, since: datetime | None = None,
                     until: datetime | None = None) -> RunHistory:
    """Read run records for a date range through the GitHub API.

    The range is asked for explicitly and every page is fetched, so coverage is
    known rather than guessed: a fixed "most recent N runs" cap would silently
    miss the one run that matters in a busy repository, and would leave the
    retention horizon unknowable.
    """
    query = "per_page=100"
    if since or until:
        lo = since.date().isoformat() if since else "*"
        hi = until.date().isoformat() if until else "*"
        query += f"&created={lo}..{hi}"
    try:
        raw = subprocess.run(
            ["gh", "api", "--paginate", "--slurp",
             f"repos/{repo_slug}/actions/runs?{query}"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise RuntimeError(f"could not read CI runs for {repo_slug}: {e}") from e
    pages = json.loads(raw or "[]")
    runs = [run for page in pages for run in page.get("workflow_runs", [])]
    return parse_run_list(
        json.dumps({"workflow_runs": runs}),
        source=f"gh api repos/{repo_slug}/actions/runs ({query})",
        # Coverage is exactly the range requested; an unbounded query establishes
        # nothing about how far back the platform still keeps runs.
        covered_from=since,
    )


def installs_from_workflows(repo: Path, sha: str,
                            workflow_path: str | None = None) -> bool | None:
    """Whether the workflow that ran at ``sha`` unambiguously installs deps.

    The workflow file is read from git rather than from the API: it is versioned
    alongside the lockfile, so this answers what that commit's CI would have run
    — no network, no tokens, no dependence on run retention.

    ``workflow_path`` narrows the question to the file that defines the run.
    Without it the answer stays ``None`` even when *some* workflow in the repo
    installs dependencies, because an issue-comment or docs workflow installs
    nothing and attributing another file's steps to it would confirm an
    execution that never happened.
    """
    if workflow_path is None:
        return None
    try:
        body = _git_text(repo, "show", f"{sha}:{workflow_path}").lower()
    except GitError:
        return None
    return any(command in body for command in INSTALL_COMMANDS)


def annotate_installs(repo: Path, records: tuple[RunRecord, ...],
                      ) -> tuple[RunRecord, ...]:
    """Fill ``installs_dependencies`` from each run's own workflow file at its commit."""
    cache: dict[tuple[str, str | None], bool | None] = {}
    annotated = []
    for record in records:
        key = (record.head_sha, record.workflow_path)
        if key not in cache:
            cache[key] = installs_from_workflows(repo, record.head_sha,
                                                 record.workflow_path)
        annotated.append(
            RunRecord(
                run_id=record.run_id, head_sha=record.head_sha,
                started_at=record.started_at, workflow=record.workflow,
                installs_dependencies=cache[key],
                workflow_path=record.workflow_path,
                created_at=record.created_at, event=record.event,
                attempt=record.attempt,
            )
        )
    return tuple(annotated)
