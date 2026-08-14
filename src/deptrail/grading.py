"""Grade an exposure by how strongly the evidence says the malicious code ran.

A lockfile pinning a compromised version proves the pin, not the install. What a
responder needs to decide is narrower: *did an install actually happen while the
artifact was live, and therefore must these secrets be rotated?* CI run records
answer that where they exist, and this module states exactly how far each answer
reaches:

- ``CONFIRMED``  — a CI run checked out the exposing commit and started inside
  a closed window: an install ran while the artifact was known to be live.
- ``LIKELY``     — CI activity coincides with the exposure, but not on the
  exposing commit itself, the removal time is unknown, or the run on that
  commit started outside the window.
- ``POSSIBLE``   — the pin overlapped the window and nothing rules an install
  in or out. Developer machines leave no run records at all, so this is the
  honest grade for "no CI evidence", never a downgrade to safe.
- ``NO_EVIDENCE``— no exposure interval overlapped the window.

``CONFIRMED`` demands positive evidence on both axes: the run must be shown to
have installed dependencies (its steps are inspected), and it must have started
inside a recorded finite window while the artifact was live. A run we cannot
inspect, one with no known removal bound, or one that ran before the version
turned malicious does not confirm execution.

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
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

from .history import (
    Exposure,
    GitError,
    RepoFinding,
    UnreadTree,
    Verdict,
    WindowQuery,
    _git as _git_text,
    _parse_iso,
)

# Commands that unambiguously install this ecosystem's dependencies. A run whose
# workflow contains one implicates an install, but only a recorded live window can
# raise it to CONFIRMED: with an unknown removal time, registry availability and
# execution remain unproven. A step merely named "Install" may install anything.
INSTALL_COMMANDS = ("npm ci", "npm i ", "npm install", "yarn install", "yarn --frozen",
                    "pnpm install", "pnpm i ", "npm-run-all install")
# GitHub's default run retention; used only to say "the records for that window
# are probably gone", never to claim a run did or did not happen.
RETENTION = timedelta(days=90)


class ToolFailure(RuntimeError):
    """A call this tool needed did not complete.

    Its own type, because wrapping a ``CalledProcessError`` in a plain
    ``RuntimeError`` loses the one fact a caller needs — that retrying may help —
    and the report then files it as evidence that says nothing.
    """


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
    """One exposure with its grade and the facts the grade rests on.

    ``workflow_paths`` names **every** workflow behind the implicated runs. One
    push commonly fires several workflows, and each one's environment held its own
    secrets: scoping to a single file would drop the others' credentials from the
    rotation list. It is left empty when any implicated run's workflow is unknown,
    because a partial list would narrow the rotation scope on incomplete evidence.

    ``implicates_install`` says whether those runs could have installed the
    malicious version. A run with an install workflow under an open window still
    implicates installation for rotation scope, even though registry availability
    and execution are unproven. A run after a recorded removal, or one whose
    workflow installs nothing, is evidence *about* the exposure but not an install.
    """

    exposure: Exposure
    grade: Grade
    evidence: tuple[str, ...]
    run_ids: tuple[str, ...] = ()
    workflow_paths: tuple[str, ...] = ()
    implicates_install: bool = False


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
    # Notes about the CI evidence, kept apart from the walker's warnings: only the
    # latter mean the repository's history could not be read.
    ci_notes: list[str] = field(default_factory=list)
    # Trees whose dependencies were never readable — a lockfile dialect this
    # version cannot parse, or no lockfile at all. See ``worst_grade``.
    unread_trees: list[UnreadTree] = field(default_factory=list)
    # Observations that cost no evidence, printed but never acted on.
    diagnostics: list[str] = field(default_factory=list)
    # Ways the clone holds less than the repository does. Like a warning they stop
    # an all-clear; unlike a warning they point at no artifact, so they name no
    # credential either.
    incomplete: list[str] = field(default_factory=list)

    @property
    def worst_grade(self) -> Grade:
        for grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE):
            if any(g.grade is grade for g in self.graded):
                return grade
        if self.warnings or self.incomplete:
            # Evidence about a lockfile we do track was lost, or the clone never
            # held it, so an install was neither shown nor ruled out — which is
            # what POSSIBLE means. NO_EVIDENCE would claim the lockfile never held
            # a named version.
            return Grade.POSSIBLE
        # An unread tree is different: no version was seen, and none was hidden
        # from us either, so there is genuinely no evidence in any direction.
        # Grading it POSSIBLE would put every Yarn repository on a rotation list.
        # The report still refuses to prove absence — see ``OrgReport``.
        return Grade.NO_EVIDENCE

    @property
    def needs_rotation(self) -> bool:
        """Whether this repo belongs on the rotation checklist.

        POSSIBLE counts: an unprovable install is not an absent one, and the
        cost of rotating one extra credential is smaller than the cost of
        leaving a live one in an attacker's hands.

        An incomplete clone with nothing found is the exception, and it is not a
        softening: no credential is pointed at, so none goes on a checklist, and the
        exit code says "could not prove absence" on its own. Answering True here
        would also make the caller fetch a repository's secret names — an
        admin-scoped call — for a list it is then going to leave empty.
        """
        if not self.graded and not self.warnings and self.incomplete:
            return False
        return self.worst_grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE)


def _overlap_start(exposure: Exposure, query: WindowQuery) -> datetime:
    """The first instant the pin and the window coincide — where an install counts.

    Only the start is returned because only the start is used. This returned the whole
    interval until review pointed out that no caller ever read the end, so the
    arithmetic for it was dead and the tests written for it asserted a value no report
    could show.
    """
    return max(exposure.since, query.window_start)


# Events whose run checks out the head commit itself. A ``pull_request`` run
# checks out an ephemeral merge of head and base instead, so what it installed is
# that merge — it can support a grade but never confirm one for this commit.
HEAD_CHECKOUT_EVENTS = ("push", "workflow_dispatch", "schedule", "release")


def _known_workflows(runs: list[RunRecord]) -> tuple[str, ...]:
    """Every implicated workflow, or nothing if even one of them is unknown."""
    if any(r.workflow_path is None for r in runs):
        return ()
    return tuple(sorted({r.workflow_path for r in runs if r.workflow_path}))


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
    during = [r for r in on_commit if live_start <= r.at and query.covers(r.at)]
    confirming = [r for r in during
                  if r.installs_dependencies is True
                  and r.event in HEAD_CHECKOUT_EVENTS]

    if confirming:
        run = confirming[0]
        availability_known = query.window_end is not None
        if availability_known:
            evidence = (
                f"run {run.run_id} ({run.workflow}, {run.event}) built "
                f"{exposure.commit[:8]} at {run.at.isoformat()}, while "
                f"{exposure.version} was still served by the registry",
                f"the workflows at that commit install dependencies, so "
                f"{exposure.version} executed",
            )
        else:
            evidence = (
                f"run {run.run_id} ({run.workflow}, {run.event}) built "
                f"{exposure.commit[:8]} at {run.at.isoformat()}, at or after the "
                f"publish time for {exposure.version}",
                "the workflows at that commit install dependencies, but the registry "
                f"removal time is unknown; availability and {exposure.version} "
                "execution are not proven",
            )
        return GradedExposure(
            exposure=exposure,
            grade=Grade.CONFIRMED if availability_known else Grade.LIKELY,
            evidence=evidence,
            run_ids=tuple(r.run_id for r in confirming),
            workflow_paths=_known_workflows(confirming),
            implicates_install=True,
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
        timing = (
            f"while {exposure.version} was still served, but {why}"
            if query.window_end is not None else
            f"at or after the publish time for {exposure.version}; the registry removal "
            f"time is unknown, and {why}"
        )
        return GradedExposure(
            exposure=exposure, grade=Grade.LIKELY,
            evidence=(
                f"run {run.run_id} ({run.workflow}, {run.event}) built "
                f"{exposure.commit[:8]} at {run.at.isoformat()}, {timing}",
            ),
            run_ids=tuple(r.run_id for r in during),
            workflow_paths=_known_workflows(during),
            # An uninspectable workflow may well have installed; one that
            # provably installs nothing did not.
            implicates_install=any(r.installs_dependencies is not False for r in during),
        )

    # Nothing is "after" an open end. Without a recorded removal we cannot say the
    # artifact was gone by the time a run built the commit, and claiming it would
    # downgrade a live exposure on an assertion nobody measured.
    later = ([] if query.window_end is None
             else [r for r in on_commit if r.at > query.window_end])
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
            workflow_paths=_known_workflows(later),
            implicates_install=False,  # it ran after the artifact was gone
        )

    if not history.covers(live_start):
        return GradedExposure(
            exposure=exposure, grade=Grade.POSSIBLE,
            evidence=(
                f"no CI records reach back to {live_start.isoformat()} "
                f"(source: {history.source}); an install cannot be ruled out",
            ),
        )

    period = (
        f"while {exposure.version} was served"
        if query.window_end is not None else
        f"at or after the publish time for {exposure.version} "
        "(registry removal time unknown)"
    )
    return GradedExposure(
        exposure=exposure, grade=Grade.POSSIBLE,
        evidence=(
            f"no CI run built {exposure.commit[:8]} {period}; a developer machine "
            "install leaves no record, so this cannot be cleared",
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
        unread_trees=list(finding.unread_trees),
        diagnostics=list(finding.diagnostics),
        incomplete=list(finding.incomplete),
    )
    graded.graded.extend(grade_exposure(e, query, history) for e in finding.exposures)

    if finding.exposures:
        earliest = min(_overlap_start(e, query) for e in finding.exposures)
        newest = max((r.at for r in history.records), default=None)
        beyond_retention = newest is not None and earliest < newest - RETENTION
        if not history.covers(earliest) or beyond_retention:
            graded.ci_notes.append(
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


def _coverage_doubt(pages: list, runs: list, announced: object,
                    until: datetime | None = None) -> str | None:
    """Why this read cannot certify the range it asked for, or ``None`` if it can.

    Three signals, because the endpoint gives no direct one. It stops at a fixed number of
    items, newest first, with HTTP 200 and nothing in the body to say so.

    Counting is necessary and not sufficient. `--paginate` walks offsets, and a run created
    between two page requests shifts every later page by one: a boundary run arrives twice
    while the oldest is pushed off the end, and the total collected is unchanged. Measured
    at 200 collected against 199 distinct, with the oldest run missing and the count still
    matching — which is why duplicate ids are checked too.

    The third signal is `total_count` disagreeing between pages. Against the live API it is
    identical on every non-empty page (1045 across ten of them for `expressjs/express`) and
    0 on the empty page past the cap, so a difference among the non-empty ones means the
    list moved underfoot. Empty pages are excluded for exactly that reason.
    """
    if not pages:
        return "the API returned no pages at all, so nothing was read"
    # `type(...) is int` and not `isinstance`: `True` is an instance of `int` in Python, so
    # a malformed `"total_count": true` passed a fail-closed check as a number.
    if type(announced) is not int:
        return f"the API reported no usable total ({announced!r}), so the read cannot be checked"
    if announced != len(runs):
        return (f"the API returned {len(runs)} run(s) against a reported total of "
                f"{announced}, newest first, so the oldest part of the range was not "
                "delivered")
    ids = [run.get("id") for run in runs if run.get("id") is not None]
    if len(ids) != len(set(ids)):
        return (f"{len(ids) - len(set(ids))} run(s) arrived twice, so the list shifted "
                "between page requests and an older run was pushed out of it")
    totals = {page.get("total_count") for page in pages if page.get("workflow_runs")}
    if len(totals) > 1:
        return (f"the reported total changed between pages ({sorted(map(str, totals))}), "
                "so the list shifted while it was being read")
    # And the three signals above are still only necessary, not sufficient. A run created
    # between two page requests shifts the offsets while an unrelated deletion restores the
    # total: same count, same total, no duplicate id, and a run missing from the middle.
    # Nothing in an offset-paginated response rules that out.
    #
    # What does rule it out is the range itself. A run is created with `created_at` of now,
    # so a range whose upper bound is already past cannot gain one, and a deletion lowers
    # the count and is caught above. A single page cannot be shifted at all. Anything else
    # — several pages reaching up to today — is the case that cannot be certified.
    stable = until and until.astimezone(timezone.utc).date() < datetime.now(
        timezone.utc).date()
    if len(pages) > 1 and not stable:
        return (f"{len(pages)} pages were read over a range that reaches the present, and "
                "offset pagination gives no snapshot — a run created between two requests "
                "shifts the rest and can hide one without changing any count")
    return None


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
        # Normalised to UTC before the date is taken. `created=` filters by date, and a
        # bound written in another offset lands on a different day: a window opening at
        # 2025-11-25T01:00+09:00 is 2025-11-24 in UTC, and asking from the 25th skipped the
        # first hours of the window it was meant to cover.
        lo = since.astimezone(timezone.utc).date().isoformat() if since else "*"
        hi = until.astimezone(timezone.utc).date().isoformat() if until else "*"
        query += f"&created={lo}..{hi}"
    try:
        raw = subprocess.run(
            ["gh", "api", "--paginate", "--slurp",
             f"repos/{repo_slug}/actions/runs?{query}"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise ToolFailure(f"could not read CI runs for {repo_slug}: {e}") from e
    pages = json.loads(raw or "[]")
    runs = [run for page in pages for run in page.get("workflow_runs", [])]
    source = f"gh api repos/{repo_slug}/actions/runs ({query})"
    # The endpoint stops at a fixed number of items, newest first, with HTTP 200 and no
    # marker in the body — the only way to notice is that page 1 announced a larger
    # `total_count` than the number of runs that arrived. Measured against
    # `expressjs/express`, an ordinary repository: an eleven-month range reports 1,045
    # runs and returns the newest thousand, so the runs from the *incident* are exactly
    # the ones missing. Believing the requested range was covered then reports that
    # period as quiet rather than as unanswered, which is a false clean.
    announced = pages[0].get("total_count") if pages else None
    if doubt := _coverage_doubt(pages, runs, announced, until):
        unverified = parse_run_list(
            json.dumps({"workflow_runs": runs}),
            source=f"{source}: {doubt} — narrow the window, or the range of repositories",
            covered_from=None,
        )
        # No horizon at all, not the oldest record's timestamp. That would claim the range
        # from there to `until` is contiguous, and none of the signals above says where the
        # hole is: a read can deliver August and June while July is missing, and
        # `min(r.at)` then answers "covered" straight across it. The records stay as
        # positive evidence — a run that confirms still confirms — but they are not
        # evidence of absence.
        return unverified
    return parse_run_list(
        json.dumps({"workflow_runs": runs}),
        source=source,
        # Everything the filter matched arrived, so the requested range really was
        # covered — including the case where it matched nothing, which is evidence
        # that no run happened rather than evidence of a truncated read.
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
