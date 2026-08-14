"""Tests for evidence grading — the rules that decide what must be rotated.

Grades are asserted through their consequences, not their spelling: what a
responder does with CONFIRMED and POSSIBLE differs, and what they must never see
is a repo cleared because no run record survived.
"""
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from deptrail.grading import (
    Grade,
    RunHistory,
    RunRecord,
    annotate_installs,
    grade_exposure,
    parse_run_list,
    grade_finding,
    installs_from_workflows,
    runs_from_github,
)
from dataclasses import replace

from deptrail.history import Exposure, RepoFinding, Verdict, WindowQuery

WINDOW = WindowQuery(
    package="chalk",
    malicious_versions=frozenset({"5.6.1"}),
    window_start=datetime(2025, 11, 24, tzinfo=timezone.utc),
    window_end=datetime(2025, 11, 26, 23, 59, 59, tzinfo=timezone.utc),
)
COMMIT = "a" * 40
OTHER = "b" * 40


def exposure(*, since=datetime(2025, 11, 25, tzinfo=timezone.utc),
             until=datetime(2025, 11, 28, tzinfo=timezone.utc), commit=COMMIT) -> Exposure:
    return Exposure(
        lockfile_path="package-lock.json", version="5.6.1", since=since, until=until,
        commit=commit, chain=("express", "debug", "chalk"), evidence="interval:HEAD",
    )


def run(*, sha=COMMIT, at=datetime(2025, 11, 25, 10, tzinfo=timezone.utc),
        installs=True, run_id="1", created=None, event="push") -> RunRecord:
    """A run that installs dependencies on a head-checkout event by default."""
    return RunRecord(run_id=run_id, head_sha=sha, started_at=at, workflow="CI",
                     installs_dependencies=installs, created_at=created, event=event)


def history(*records, oldest=datetime(2025, 11, 1, tzinfo=timezone.utc)) -> RunHistory:
    return RunHistory(records=records, oldest_available=oldest, source="test")


class TestConfirmed:
    def test_run_on_exposing_commit_inside_window(self):
        graded = grade_exposure(exposure(), WINDOW, history(run()))
        assert graded.grade is Grade.CONFIRMED
        assert graded.run_ids == ("1",)
        assert any("still served by the registry" in e for e in graded.evidence)

    def test_confirmed_cites_the_commit_and_version(self):
        graded = grade_exposure(exposure(), WINDOW, history(run()))
        joined = " ".join(graded.evidence)
        assert COMMIT[:8] in joined and "5.6.1" in joined

    def test_run_that_provably_installs_nothing_is_not_confirmed(self):
        graded = grade_exposure(exposure(), WINDOW, history(run(installs=False)))
        assert graded.grade is Grade.LIKELY
        assert any("install no dependencies" in e for e in graded.evidence)

    def test_uninspectable_run_cannot_confirm(self):
        # We could not read the run's steps, so we cannot claim it installed.
        graded = grade_exposure(exposure(), WINDOW, history(run(installs=None)))
        assert graded.grade is Grade.LIKELY
        assert any("could not be read" in e for e in graded.evidence)


class TestLikely:
    def test_run_on_exposing_commit_after_the_artifact_was_pulled(self):
        # The commit still pinned 5.6.1, but by then npm had removed it: the
        # install may have failed, so this cannot be CONFIRMED.
        late = datetime(2025, 11, 27, 12, tzinfo=timezone.utc)
        graded = grade_exposure(exposure(), WINDOW, history(run(at=late)))
        assert graded.grade is Grade.LIKELY
        assert any("no longer served" in e for e in graded.evidence)

    def test_runs_on_other_commits_are_not_evidence(self):
        # That run built a different lockfile state, so it says nothing about
        # this exposure; counting it would inflate the incident.
        graded = grade_exposure(exposure(), WINDOW, history(run(sha=OTHER)))
        assert graded.grade is Grade.POSSIBLE
        assert any("no CI run built" in e for e in graded.evidence)


class TestPossible:
    def test_no_runs_at_all_is_possible_not_clean(self):
        graded = grade_exposure(exposure(), WINDOW, history())
        assert graded.grade is Grade.POSSIBLE
        assert any("developer machine" in e for e in graded.evidence)

    def test_expired_records_are_possible_with_the_reason(self):
        # Records only reach back a week; the window is months old.
        recent = RunHistory(records=(), oldest_available=datetime(2026, 8, 1, tzinfo=timezone.utc),
                            source="gh run list")
        graded = grade_exposure(exposure(), WINDOW, recent)
        assert graded.grade is Grade.POSSIBLE
        assert any("no CI records reach back" in e for e in graded.evidence)

    def test_unknown_horizon_never_reads_as_cleared(self):
        graded = grade_exposure(exposure(), WINDOW, RunHistory(source="truncated page"))
        assert graded.grade is Grade.POSSIBLE
        assert any("cannot be ruled out" in e for e in graded.evidence)


class TestWindowIntersection:
    def test_run_before_the_pin_is_no_evidence_of_malicious_install(self):
        # The run fetched the clean version, so it is not evidence at all —
        # escalating it to LIKELY would overstate the incident's scope.
        early = datetime(2025, 11, 24, 1, tzinfo=timezone.utc)
        graded = grade_exposure(exposure(), WINDOW, history(run(at=early)))
        assert graded.grade is Grade.POSSIBLE

    def test_run_months_before_the_window_does_not_escalate(self):
        exp = exposure(since=datetime(2025, 1, 1, tzinfo=timezone.utc), until=None)
        old_run = run(at=datetime(2025, 6, 1, tzinfo=timezone.utc))
        graded = grade_exposure(exp, WINDOW, history(old_run,
                                                     oldest=datetime(2024, 12, 1, tzinfo=timezone.utc)))
        assert graded.grade is Grade.POSSIBLE

    def test_unrelated_run_before_the_pin_is_only_possible(self):
        early = datetime(2025, 11, 24, 1, tzinfo=timezone.utc)
        graded = grade_exposure(exposure(), WINDOW, history(run(sha=OTHER, at=early)))
        assert graded.grade is Grade.POSSIBLE

    def test_rebuilding_the_old_commit_after_the_fix_still_confirms(self):
        # The fix landed on 11-25, but checking out the old commit on 11-26 —
        # while the registry still served the artifact — installs it anyway.
        exp = exposure(until=datetime(2025, 11, 25, 12, tzinfo=timezone.utc))
        after = datetime(2025, 11, 26, tzinfo=timezone.utc)
        graded = grade_exposure(exp, WINDOW, history(run(at=after)))
        assert graded.grade is Grade.CONFIRMED

    def test_run_after_the_artifact_was_pulled_is_only_likely(self):
        after_window = datetime(2025, 11, 28, tzinfo=timezone.utc)
        graded = grade_exposure(exposure(), WINDOW, history(run(at=after_window)))
        assert graded.grade is Grade.LIKELY
        assert any("no longer served" in e for e in graded.evidence)

    def test_still_pinned_exposure_uses_the_window_end(self):
        exp = exposure(until=None)
        graded = grade_exposure(exp, WINDOW, history(run(at=WINDOW.window_end)))
        assert graded.grade is Grade.CONFIRMED


class TestRerunTimestamps:
    def test_rerun_cannot_move_an_install_out_of_the_window(self):
        # A re-run in December rewrote startedAt; createdAt still points at the
        # original queue time inside the window.
        rerun = run(at=datetime(2025, 12, 20, tzinfo=timezone.utc),
                    created=datetime(2025, 11, 25, 10, tzinfo=timezone.utc))
        graded = grade_exposure(exposure(), WINDOW, history(rerun))
        assert graded.grade is Grade.CONFIRMED


class TestIndeterminateNeverClears:
    """A repo whose history could not be read must stay on the checklist."""

    @pytest.mark.parametrize("warning", [
        "shallow clone: history is truncated, absence of exposure is not evidence",
        "package-lock.json@abc123: snapshot unreadable (object missing)",
        "package-lock.json: discovered in refs but no walkable history",
    ])
    def test_unreadable_history_is_possible_not_no_evidence(self, warning):
        finding = RepoFinding(repo=Path("/tmp/repo"), warnings=[warning])
        graded = grade_finding(finding, WINDOW, history(run()))
        assert graded.verdict is Verdict.INDETERMINATE
        assert graded.worst_grade is Grade.POSSIBLE
        assert graded.needs_rotation

    def test_readable_and_unexposed_repo_is_cleared(self):
        graded = grade_finding(RepoFinding(repo=Path("/tmp/repo")), WINDOW, history(run()))
        assert graded.worst_grade is Grade.NO_EVIDENCE and not graded.needs_rotation


class TestAdvisoryIdentity:
    def test_coverage_warning_and_identity_travel_with_the_grades(self):
        graded = grade_finding(
            RepoFinding(repo=Path("/tmp/repo"), exposures=[exposure()]), WINDOW,
            history(run()), advisory_id="GHSA-xxxx",
            coverage_warning="advisory GHSA-xxxx declares partial coverage",
        )
        assert graded.advisory_id == "GHSA-xxxx"
        assert graded.package == "chalk"
        assert "partial coverage" in graded.coverage_warning


class TestFindingRollup:
    def _finding(self, *exposures) -> RepoFinding:
        return RepoFinding(repo=Path("/tmp/repo"), exposures=list(exposures))

    def test_worst_grade_wins(self):
        # One exposure has a run on its own commit (CONFIRMED); the other has no
        # run of its own (POSSIBLE). The repo is graded by the strongest.
        graded = grade_finding(
            self._finding(exposure(), exposure(commit=OTHER)), WINDOW, history(run())
        )
        assert {g.grade for g in graded.graded} == {Grade.CONFIRMED, Grade.POSSIBLE}
        assert graded.worst_grade is Grade.CONFIRMED

    def test_no_exposures_means_no_evidence_and_no_rotation(self):
        graded = grade_finding(self._finding(), WINDOW, history(run()))
        assert graded.worst_grade is Grade.NO_EVIDENCE
        assert not graded.needs_rotation

    @pytest.mark.parametrize("grade_history,expected", [
        (lambda: history(run()), True),                      # CONFIRMED
        (lambda: history(run(sha=OTHER)), True),             # LIKELY
        (lambda: history(), True),                           # POSSIBLE
    ])  # every grade that admits an exposure requires rotation
    def test_every_exposure_grade_requires_rotation(self, grade_history, expected):
        graded = grade_finding(self._finding(exposure()), WINDOW, grade_history())
        assert graded.needs_rotation is expected

    def test_walker_warnings_are_carried_forward(self):
        finding = RepoFinding(repo=Path("/tmp/repo"), warnings=["shallow clone: truncated"])
        graded = grade_finding(finding, WINDOW, history(run()))
        assert graded.verdict is Verdict.INDETERMINATE
        assert graded.warnings == ["shallow clone: truncated"]

    def test_expired_records_are_noted_apart_from_history_warnings(self):
        recent = RunHistory(records=(), oldest_available=datetime(2026, 8, 1, tzinfo=timezone.utc),
                            source="gh")
        graded = grade_finding(self._finding(exposure()), WINDOW, recent)
        # A CI-coverage note must not be mistaken for an unreadable history.
        assert any("absence of a run is not absence of an install" in n
                   for n in graded.ci_notes)
        assert graded.warnings == []

    def test_warning_is_not_repeated_per_exposure(self):
        recent = RunHistory(records=(), oldest_available=datetime(2026, 8, 1, tzinfo=timezone.utc),
                            source="gh")
        graded = grade_finding(
            self._finding(exposure(), exposure(commit=OTHER)), WINDOW, recent
        )
        assert sum("absence of a run" in n for n in graded.ci_notes) == 1


class TestRunHistoryHorizon:
    def test_covers_is_false_when_horizon_unknown(self):
        assert not RunHistory().covers(datetime(2025, 11, 25, tzinfo=timezone.utc))

    def test_covers_boundary_is_inclusive(self):
        moment = datetime(2025, 11, 25, tzinfo=timezone.utc)
        assert RunHistory(oldest_available=moment).covers(moment)
        assert not RunHistory(oldest_available=moment + timedelta(seconds=1)).covers(moment)


class TestInstallDetection:
    """Workflow-based install detection, shaped by replaying real workflows."""

    def _repo(self, tmp_path, files: dict[str, str]):
        repo = tmp_path / "wf"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        for name, body in files.items():
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "init"], check=True, capture_output=True,
        )
        sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                             check=True, capture_output=True, text=True).stdout.strip()
        return repo, sha

    def test_unambiguous_npm_install_is_true(self, tmp_path):
        repo, sha = self._repo(tmp_path, {
            ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: npm ci\n",
        })
        assert installs_from_workflows(repo, sha, ".github/workflows/ci.yml") is True

    def test_another_workflow_in_the_repo_does_not_answer_for_this_run(self, tmp_path):
        # A docs workflow installs nothing even though ci.yml runs npm ci.
        repo, sha = self._repo(tmp_path, {
            ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: npm ci\n",
            ".github/workflows/docs.yml": "jobs:\n  docs:\n    steps:\n      - run: make docs\n",
        })
        assert installs_from_workflows(repo, sha, ".github/workflows/docs.yml") is False

    def test_unknown_workflow_path_is_undecidable(self, tmp_path):
        repo, sha = self._repo(tmp_path, {
            ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: npm ci\n",
        })
        assert installs_from_workflows(repo, sha, None) is None

    def test_other_ecosystem_is_false(self, tmp_path):
        repo, sha = self._repo(tmp_path, {
            ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: pip install -e .\n",
        })
        assert installs_from_workflows(repo, sha, ".github/workflows/ci.yml") is False

    def test_missing_file_at_that_commit_is_undecidable(self, tmp_path):
        repo, sha = self._repo(tmp_path, {"README.md": "hi"})
        assert installs_from_workflows(repo, sha, ".github/workflows/ci.yml") is None

    def test_unrecognised_event_cannot_confirm(self, tmp_path):
        # An issue_comment run does not check out this commit's tree.
        graded = grade_exposure(exposure(), WINDOW, history(run(event="issue_comment")))
        assert graded.grade is Grade.LIKELY

    def test_ambiguous_step_name_cannot_confirm(self, tmp_path):
        # A step merely named "Install" may install anything; guessing would
        # assert an execution that never happened.
        repo, sha = self._repo(tmp_path, {
            ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - name: Install\n        run: make bootstrap\n",
        })
        assert installs_from_workflows(repo, sha, ".github/workflows/ci.yml") is False

    def test_annotate_answers_per_commit_and_workflow(self, tmp_path):
        repo, sha = self._repo(tmp_path, {
            ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: npm ci\n",
            ".github/workflows/docs.yml": "jobs:\n  docs:\n    steps:\n      - run: make docs\n",
        })
        records = (
            RunRecord(run_id="1", head_sha=sha, started_at=WINDOW.window_start,
                      workflow="CI", workflow_path=".github/workflows/ci.yml"),
            RunRecord(run_id="2", head_sha=sha, started_at=WINDOW.window_start,
                      workflow="Docs", workflow_path=".github/workflows/docs.yml"),
        )
        annotated = annotate_installs(repo, records)
        assert [r.installs_dependencies for r in annotated] == [True, False]


class TestPullRequestRuns:
    """A pull_request run installs a merge of head and base, not this tree."""

    def test_pull_request_run_cannot_confirm(self):
        graded = grade_exposure(exposure(), WINDOW,
                                history(run(event="pull_request")))
        assert graded.grade is Grade.LIKELY
        assert graded.exact_install_run is False
        assert any("merge of head and base" in e for e in graded.evidence)

    def test_push_run_can_confirm(self):
        graded = grade_exposure(exposure(), WINDOW, history(run(event="push")))
        assert graded.grade is Grade.CONFIRMED


class TestRunListParsing:
    """The collector is tested directly, on the API's own shape."""

    def _payload(self, **overrides):
        item = {
            "id": 42, "head_sha": COMMIT, "name": "CI", "event": "push",
            "run_started_at": "2025-11-25T10:00:00Z",
            "created_at": "2025-11-25T09:59:00Z", "run_attempt": 2,
        }
        item.update(overrides)
        return json.dumps({"workflow_runs": [item]})

    def test_fields_are_mapped(self):
        parsed = parse_run_list(self._payload(), source="test")
        record = parsed.records[0]
        assert record.run_id == "42" and record.event == "push"
        assert record.attempt == 2
        # A re-run rewrote run_started_at; created_at keeps the original time.
        assert record.at == datetime(2025, 11, 25, 9, 59, tzinfo=timezone.utc)

    def test_queued_run_without_start_is_skipped_and_noted(self):
        parsed = parse_run_list(
            self._payload(run_started_at=None, created_at=None), source="test"
        )
        assert parsed.records == ()
        assert "without a start time" in parsed.source

    def test_zero_date_does_not_become_a_horizon(self):
        parsed = parse_run_list(
            self._payload(run_started_at="0001-01-01T00:00:00Z", created_at=None),
            source="test",
        )
        assert parsed.records == ()
        assert not parsed.covers(datetime(2025, 1, 1, tzinfo=timezone.utc))

    def test_coverage_is_what_was_requested_not_what_came_back(self):
        asked = datetime(2025, 11, 1, tzinfo=timezone.utc)
        parsed = parse_run_list(self._payload(), source="test", covered_from=asked)
        assert parsed.covers(asked)
        assert not parsed.covers(asked - timedelta(days=1))

    def test_empty_response(self):
        assert parse_run_list("", source="test").records == ()


OPEN_WINDOW = WindowQuery(
    package="chalk",
    malicious_versions=frozenset({"5.6.1"}),
    window_start=datetime(2025, 11, 24, tzinfo=timezone.utc),
    window_end=None,
)


class TestOpenUpperBoundChangesVerdicts:
    """An unknown removal must preserve rotation without inventing execution (#23).

    A missing end cannot prove the artifact was gone, but it also cannot prove the
    artifact was available. The grade therefore keeps the install implicated and the
    credentials in scope while stating the uncertainty.
    """

    def test_a_run_after_a_closed_window_is_only_likely(self):
        after = run(at=datetime(2025, 11, 27, 10, tzinfo=timezone.utc))
        graded = grade_exposure(exposure(), WINDOW, history(after))
        # The closed window says the artifact was gone, so the install may have failed.
        assert graded.grade is Grade.LIKELY
        assert graded.implicates_install is False
        assert any("no longer served" in e for e in graded.evidence)

    def test_unknown_removal_caps_the_same_install_at_likely(self):
        exact = run()
        closed = grade_exposure(exposure(), WINDOW, history(exact))
        opened = grade_exposure(exposure(), OPEN_WINDOW, history(exact))
        assert closed.grade is Grade.CONFIRMED
        assert opened.grade is Grade.LIKELY
        assert opened.implicates_install is True
        assert closed.exact_install_run is True
        assert opened.exact_install_run is True
        joined = " ".join(opened.evidence)
        assert "removal time is unknown" in joined
        assert "availability" in joined and "not proven" in joined
        assert "still served" not in joined and "executed" not in joined

    def test_a_run_years_later_stays_likely_under_an_open_window(self):
        graded = grade_exposure(
            exposure(until=None),
            OPEN_WINDOW,
            history(run(at=datetime(2030, 1, 1, tzinfo=timezone.utc)),
                    oldest=datetime(2029, 1, 1, tzinfo=timezone.utc)),
        )
        assert graded.grade is Grade.LIKELY
        assert graded.implicates_install is True
        assert any("removal time is unknown" in e for e in graded.evidence)

    def test_an_uninspectable_open_window_run_does_not_claim_availability(self):
        graded = grade_exposure(
            exposure(), OPEN_WINDOW, history(run(installs=None)),
        )
        assert graded.grade is Grade.LIKELY
        assert graded.exact_install_run is False
        joined = " ".join(graded.evidence)
        assert "removal time is unknown" in joined
        assert "still served" not in joined

    def test_no_open_window_run_does_not_claim_a_served_period(self):
        graded = grade_exposure(exposure(), OPEN_WINDOW, history())
        assert graded.grade is Grade.POSSIBLE
        assert "registry removal time unknown" in " ".join(graded.evidence)

    def test_the_overlap_starts_at_whichever_began_later(self):
        from deptrail.grading import _overlap_start

        # The window opens first, so the pin's own start is where an install counts.
        assert _overlap_start(exposure(until=None), OPEN_WINDOW) == datetime(
            2025, 11, 25, tzinfo=timezone.utc)
        # And the reverse: a pin older than the incident counts from the window.
        early = exposure(since=datetime(2025, 1, 1, tzinfo=timezone.utc))
        assert _overlap_start(early, OPEN_WINDOW) == OPEN_WINDOW.window_start


class TestNothingIsAfterAnOpenEnd:
    def test_a_run_predating_the_pin_is_not_called_late(self):
        # `later` exists to say "the artifact was already gone". Under an open end there
        # is no such moment, and the only runs that fall through to it are ones that
        # predate the pin — a re-used sha or a skewed clock. Describing those as "after
        # the window closed" inverts the fact.
        early = run(at=datetime(2025, 11, 24, 6, tzinfo=timezone.utc))
        graded = grade_exposure(
            exposure(since=datetime(2025, 11, 25, tzinfo=timezone.utc)),
            OPEN_WINDOW, history(early),
        )
        assert graded.grade is not Grade.LIKELY
        assert not any("no longer served" in e for e in graded.evidence)
        assert graded.implicates_install is False
        assert graded.exact_install_run is False


class TestBoundaryInstants:
    """The edges of the two run filters this feature rewrote."""

    def test_a_run_at_the_exact_open_window_start_is_likely(self):
        # `during` uses `live_start <= r.at`. Making it strict would drop evidence that
        # an install workflow ran and quietly move the credential from REPO_WIDE to
        # DEVELOPER scope.
        at_start = run(at=OPEN_WINDOW.window_start)
        graded = grade_exposure(
            exposure(since=datetime(2025, 11, 20, tzinfo=timezone.utc), until=None),
            OPEN_WINDOW, history(at_start),
        )
        assert graded.grade is Grade.LIKELY
        assert graded.implicates_install is True

    def test_a_run_at_the_exact_window_end_confirms(self):
        at_end = run(at=WINDOW.window_end)
        graded = grade_exposure(
            exposure(since=datetime(2025, 11, 25, tzinfo=timezone.utc), until=None),
            WINDOW, history(at_end),
        )
        assert graded.grade is Grade.CONFIRMED

    def test_a_run_at_the_exact_window_end_is_not_late(self):
        # `later` uses `r.at > window_end`. At `>=` the same run is described as having
        # run "after ... when 5.6.1 was no longer served", which is false at the
        # inclusive edge.
        late_side = WindowQuery(
            package="chalk", malicious_versions=frozenset({"5.6.1"}),
            window_start=datetime(2025, 11, 24, tzinfo=timezone.utc),
            window_end=datetime(2025, 11, 26, 23, 59, 59, tzinfo=timezone.utc),
        )
        at_end = run(at=late_side.window_end)
        graded = grade_exposure(
            exposure(since=datetime(2025, 11, 27, tzinfo=timezone.utc), until=None),
            late_side, history(at_end),
        )
        assert not any("no longer served" in e for e in graded.evidence)


class TestTruncatedRunListIsNotCoverage:
    """The runs endpoint stops at a fixed count, newest first, with HTTP 200.

    Nothing in the body says so — the only signal is that page 1 announced a larger
    `total_count` than the number of runs that arrived. Believing the requested range
    was covered reports the incident period as quiet rather than unanswered, and for a
    lockfile outside the repository root that demotion deletes the finding: measured at
    exit 0 with `scan_complete: true` for a repository whose CI installed chalk 5.6.1.

    An open-ended window makes the range wide enough to hit the cap on ordinary
    repositories — `expressjs/express` reports 1,045 runs over eleven months.
    """

    SINCE = datetime(2025, 9, 7, tzinfo=timezone.utc)

    def _gh(self, monkeypatch, *, total, returned):
        """Fake `gh api --paginate --slurp`, newest-first and capped like the real one."""
        import subprocess as sp

        import deptrail.grading as grading

        # The runs that arrive are the newest ones, and they built later commits — the
        # runs on the exposing commit are exactly the ones the cap dropped.
        newest = datetime(2026, 8, 1, tzinfo=timezone.utc)
        runs = [{"id": i, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": (newest - timedelta(hours=i)).isoformat()}
                for i in range(returned)]
        page = {"total_count": total, "workflow_runs": runs}
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            a[0] if a else [], 0, stdout=json.dumps([page]), stderr=""))
        return runs

    def test_a_truncated_read_claims_no_horizon_at_all(self, monkeypatch):
        self._gh(monkeypatch, total=1045, returned=1000)
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        # Not the oldest record's timestamp: that would claim the range from there to the
        # end is contiguous, and nothing in a paginated response says where the hole is.
        assert history.oldest_available is None
        assert not history.covers(self.SINCE)
        assert "1000 run(s) against a reported total of 1045" in history.source

    def test_a_hole_between_the_records_is_not_covered_over(self, monkeypatch):
        import subprocess as sp

        import deptrail.grading as grading

        # August and June arrive, July is missing. A horizon taken from the oldest record
        # answers "covered" straight across it.
        runs = [{"id": 1, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-08-01T00:00:00+00:00"},
                {"id": 3, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-06-01T00:00:00+00:00"}]
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout=json.dumps([{"total_count": 3, "workflow_runs": runs}]), stderr=""))
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert history.oldest_available is None
        assert not history.covers(datetime(2026, 7, 1, tzinfo=timezone.utc))

    def test_the_delivered_runs_are_still_positive_evidence(self, monkeypatch):
        import subprocess as sp

        import deptrail.grading as grading

        # Refusing to certify coverage must not discard what arrived. With no recorded
        # removal time, the run proves an install workflow ran but not that the artifact
        # was available.
        runs = [{"id": 1, "head_sha": COMMIT, "event": "push", "name": "CI",
                 "path": ".github/workflows/ci.yml",
                 "run_started_at": "2025-11-25T10:00:00+00:00"},
                {"id": 2, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-08-01T00:00:00+00:00"}]
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout=json.dumps([{"total_count": 99, "workflow_runs": runs}]),
            stderr=""))
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert history.oldest_available is None
        graded = grade_exposure(
            exposure(until=None),
            WindowQuery(package="chalk", malicious_versions=frozenset({"5.6.1"}),
                        window_start=datetime(2025, 11, 24, tzinfo=timezone.utc),
                        window_end=None),
            replace(history, records=tuple(
                r if r.run_id != "1" else replace(r, installs_dependencies=True)
                for r in history.records)),
        )
        assert graded.grade is Grade.LIKELY
        assert graded.implicates_install is True

    def test_a_complete_read_still_claims_the_range(self, monkeypatch):
        self._gh(monkeypatch, total=3, returned=3)
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert history.oldest_available == self.SINCE
        assert history.covers(self.SINCE)
        assert "reported total" not in history.source

    def test_an_empty_range_is_evidence_not_truncation(self, monkeypatch):
        self._gh(monkeypatch, total=0, returned=0)
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        # Nothing matched the filter, which means no run happened — real evidence. A
        # truncated read must not be confused with a quiet repository, nor the reverse.
        assert history.oldest_available == self.SINCE
        assert history.covers(self.SINCE)

    @pytest.mark.parametrize("odd", [
        {"id": 9, "head_sha": OTHER, "event": "push", "name": "CI",
         "run_started_at": "0001-01-01T00:00:00Z"},
        {"id": 9, "head_sha": OTHER, "event": "push", "name": "CI",
         "created_at": "2025-11-05T00:00:00+00:00",
         "run_started_at": "2025-11-20T00:00:00+00:00"},
        {"id": 9, "head_sha": OTHER, "event": "push", "name": "CI"},
    ])
    def test_no_shape_of_run_can_produce_a_horizon_under_doubt(self, monkeypatch, odd):
        import subprocess as sp

        import deptrail.grading as grading

        # Earlier attempts derived the horizon from the runs, and each shape here broke a
        # different one: a zero date claimed coverage back to year 1, a re-run's rewritten
        # start put the horizon after records the history was holding, and a run with no
        # timestamp at all was dropped after being counted. Deriving nothing retires all
        # three at once, so the invariant is asserted rather than the arithmetic.
        runs = [{"id": 1, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-08-01T00:00:00+00:00"}, odd]
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout=json.dumps([{"total_count": 99, "workflow_runs": runs}]),
            stderr=""))
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert history.oldest_available is None
        assert not history.covers(datetime(1970, 1, 1, tzinfo=timezone.utc))
        assert not history.covers(self.SINCE)

    def test_a_count_that_disagrees_upward_is_not_coverage_either(self, monkeypatch):
        import subprocess as sp

        import deptrail.grading as grading

        # More runs than announced means the list shifted mid-pagination; the count
        # cannot certify the read in either direction.
        runs = [{"id": i, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": f"2026-08-0{i + 1}T00:00:00+00:00"} for i in range(3)]
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout=json.dumps([{"total_count": 2, "workflow_runs": runs}]),
            stderr=""))
        assert not runs_from_github("o/r", since=self.SINCE, until=None).covers(self.SINCE)

    def test_no_pages_at_all_claims_nothing(self, monkeypatch):
        import subprocess as sp

        import deptrail.grading as grading

        # `gh` printed nothing. Zero records plus a claim that the whole range was covered
        # is the shape of a scan that never looked reporting that it looked.
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout="[]", stderr=""))
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert history.records == ()
        assert history.oldest_available is None
        assert not history.covers(self.SINCE)

    def test_pagination_drift_is_not_coverage_even_when_the_count_matches(self, monkeypatch):
        import subprocess as sp

        import deptrail.grading as grading

        # `--paginate` walks offsets. A run created between two page requests shifts every
        # later page by one: a boundary run arrives twice and the oldest is pushed off the
        # end, while the total collected is unchanged. Counting alone certifies a read with
        # a hole in the middle of it.
        def page(ids, month, total):
            return {"total_count": total, "workflow_runs": [
                {"id": i, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": f"2026-{month:02d}-01T00:00:00+00:00"} for i in ids]}

        pages = [page(range(200, 100, -1), 8, 200), page(range(101, 1, -1), 7, 201)]
        collected = [r["id"] for p in pages for r in p["workflow_runs"]]
        assert len(collected) == 200 and len(set(collected)) == 199 and 1 not in collected
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout=json.dumps(pages), stderr=""))
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert not history.covers(self.SINCE)
        assert "arrived twice" in history.source

    def test_a_total_that_changes_between_pages_is_not_coverage(self, monkeypatch):
        import subprocess as sp

        import deptrail.grading as grading

        # Page 1's count must AGREE with what arrived, and the ids must be distinct, so
        # that the disagreement between pages is the only thing left to notice. A fixture
        # that also fails the count check tests the count check twice and this not at all.
        pages = [
            {"total_count": 2, "workflow_runs": [
                {"id": 1, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-08-01T00:00:00+00:00"}]},
            {"total_count": 99, "workflow_runs": [
                {"id": 2, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-07-01T00:00:00+00:00"}]},
        ]
        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout=json.dumps(pages), stderr=""))
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert not history.covers(self.SINCE)
        assert "changed between pages" in history.source

    def _pages(self, monkeypatch, pages):
        import subprocess as sp

        import deptrail.grading as grading

        monkeypatch.setattr(grading.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            [], 0, stdout=json.dumps(pages), stderr=""))

    REAL_SHAPE = [
        {"total_count": 2, "workflow_runs": [
            {"id": i, "head_sha": OTHER, "event": "push", "name": "CI",
             "run_started_at": f"2025-09-0{i}T00:00:00+00:00"} for i in (1, 2)]},
        {"total_count": 0, "workflow_runs": []},
    ]

    def test_a_closed_past_range_over_several_pages_is_certified(self, monkeypatch):
        # The live API reports the same total on every non-empty page and 0 on the empty
        # one past the cap, so empty pages must not count toward the disagreement test. A
        # range that ended before today cannot gain a run, so paging it is safe.
        self._pages(monkeypatch, self.REAL_SHAPE)
        history = runs_from_github(
            "o/r", since=self.SINCE,
            until=datetime(2025, 9, 30, tzinfo=timezone.utc))
        assert history.covers(self.SINCE)

    def test_the_same_pages_over_a_range_reaching_today_are_not(self, monkeypatch):
        # Offset pagination gives no snapshot. A run created between two requests shifts
        # the rest and can hide one without changing any count, and a range that reaches
        # the present is exactly where runs get created.
        self._pages(monkeypatch, self.REAL_SHAPE)
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert not history.covers(self.SINCE)
        assert "no snapshot" in history.source

    def test_a_single_page_reaching_today_is_certified(self, monkeypatch):
        # One page cannot be shifted by an offset, so there is nothing to doubt.
        self._pages(monkeypatch, [self.REAL_SHAPE[0]])
        assert runs_from_github("o/r", since=self.SINCE, until=None).covers(self.SINCE)

    def test_a_balanced_drift_is_refused_by_the_range_rule(self, monkeypatch):
        # The shape that defeats all three counting signals: one run created and one
        # already-read run deleted, so the total, the collected count and the distinctness
        # of the ids are all unchanged while a run is missing from the middle.
        pages = [
            {"total_count": 200, "workflow_runs": [
                {"id": i, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-08-01T00:00:00+00:00"} for i in range(200, 100, -1)]},
            {"total_count": 200, "workflow_runs": [
                {"id": i, "head_sha": OTHER, "event": "push", "name": "CI",
                 "run_started_at": "2026-07-01T00:00:00+00:00"} for i in range(100, 0, -1)]},
        ]
        collected = [r["id"] for p in pages for r in p["workflow_runs"]]
        assert len(collected) == len(set(collected)) == 200
        self._pages(monkeypatch, pages)
        assert not runs_from_github("o/r", since=self.SINCE, until=None).covers(self.SINCE)

    def test_a_boolean_total_is_not_a_number(self, monkeypatch):
        # `isinstance(True, int)` is true in Python, so a malformed `"total_count": true`
        # passed a check written to fail closed on anything that is not a number.
        self._pages(monkeypatch, [{"total_count": True, "workflow_runs": [
            {"id": 1, "head_sha": OTHER, "event": "push", "name": "CI",
             "run_started_at": "2026-08-01T00:00:00+00:00"}]}])
        history = runs_from_github("o/r", since=self.SINCE, until=None)
        assert not history.covers(self.SINCE)
        assert "no usable total" in history.source

    def test_a_total_that_is_missing_or_not_a_number_is_not_coverage(self, monkeypatch):
        import subprocess as sp

        import deptrail.grading as grading

        run = {"id": 1, "head_sha": OTHER, "event": "push", "name": "CI",
               "run_started_at": "2026-08-01T00:00:00+00:00"}
        # Without a usable total there is nothing to check the read against, and "we could
        # not check" is not "we saw everything". Fail closed.
        for total in ({}, {"total_count": None}, {"total_count": "many"}):
            monkeypatch.setattr(grading.subprocess, "run",
                                lambda *a, _t=total, **k: sp.CompletedProcess(
                                    [], 0, stdout=json.dumps([{**_t, "workflow_runs": [run]}]),
                                    stderr=""))
            history = runs_from_github("o/r", since=self.SINCE, until=None)
            assert not history.covers(self.SINCE), total
            assert "no usable total" in history.source, total
