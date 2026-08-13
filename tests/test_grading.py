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
)
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
    """An unknown removal time must widen the answer, never narrow it (#23).

    The right edge of a window is recorded nowhere, so a closed one is an assertion.
    These are the places where believing that assertion clears a repository that a
    responder would have wanted flagged.
    """

    def test_a_run_after_a_closed_window_is_only_likely(self):
        after = run(at=datetime(2025, 11, 27, 10, tzinfo=timezone.utc))
        graded = grade_exposure(exposure(), WINDOW, history(after))
        # The closed window says the artifact was gone, so the install may have failed.
        assert graded.grade is Grade.LIKELY
        assert graded.implicates_install is False
        assert any("no longer served" in e for e in graded.evidence)

    def test_the_same_run_is_confirmed_when_the_window_never_closed(self):
        after = run(at=datetime(2025, 11, 27, 10, tzinfo=timezone.utc))
        graded = grade_exposure(exposure(), OPEN_WINDOW, history(after))
        # Nothing is "after" an end nobody recorded. Downgrading here would rest the
        # whole conclusion on a number the ecosystem does not publish.
        assert graded.grade is Grade.CONFIRMED
        assert graded.implicates_install is True
        assert not any("no longer served" in e for e in graded.evidence)

    def test_a_run_years_later_still_counts_under_an_open_window(self):
        graded = grade_exposure(
            exposure(until=None),
            OPEN_WINDOW,
            history(run(at=datetime(2030, 1, 1, tzinfo=timezone.utc)),
                    oldest=datetime(2029, 1, 1, tzinfo=timezone.utc)),
        )
        assert graded.grade is Grade.CONFIRMED

    def test_an_open_window_and_a_still_pinned_lockfile_leave_the_overlap_open(self):
        from deptrail.grading import _overlap

        start, end = _overlap(exposure(until=None), OPEN_WINDOW)
        assert start == datetime(2025, 11, 25, tzinfo=timezone.utc)
        assert end is None

    def test_a_closing_pin_still_closes_the_overlap_under_an_open_window(self):
        from deptrail.grading import _overlap

        _, end = _overlap(exposure(), OPEN_WINDOW)
        # The pin ended even though the artifact's removal was never recorded, so the
        # overlap ends with the pin.
        assert end == datetime(2025, 11, 28, tzinfo=timezone.utc)


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
