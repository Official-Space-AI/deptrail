"""Tests for evidence grading — the rules that decide what must be rotated.

Grades are asserted through their consequences, not their spelling: what a
responder does with CONFIRMED and POSSIBLE differs, and what they must never see
is a repo cleared because no run record survived.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from deptrail.grading import (
    Grade,
    RunHistory,
    RunRecord,
    grade_exposure,
    grade_finding,
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
        installs=True, run_id="1", created=None) -> RunRecord:
    """A run that installs dependencies by default — the confirming shape."""
    return RunRecord(run_id=run_id, head_sha=sha, started_at=at, workflow="CI",
                     installs_dependencies=installs, created_at=created)


def history(*records, oldest=datetime(2025, 11, 1, tzinfo=timezone.utc)) -> RunHistory:
    return RunHistory(records=records, oldest_available=oldest, source="test")


class TestConfirmed:
    def test_run_on_exposing_commit_inside_window(self):
        graded = grade_exposure(exposure(), WINDOW, history(run()))
        assert graded.grade is Grade.CONFIRMED
        assert graded.run_ids == ("1",)
        assert any("pinned and live" in e for e in graded.evidence)

    def test_confirmed_cites_the_commit_and_version(self):
        graded = grade_exposure(exposure(), WINDOW, history(run()))
        joined = " ".join(graded.evidence)
        assert COMMIT[:8] in joined and "5.6.1" in joined

    def test_run_that_provably_installs_nothing_is_not_confirmed(self):
        graded = grade_exposure(exposure(), WINDOW, history(run(installs=False)))
        assert graded.grade is Grade.LIKELY
        assert any("installs no dependencies" in e for e in graded.evidence)

    def test_uninspectable_run_cannot_confirm(self):
        # We could not read the run's steps, so we cannot claim it installed.
        graded = grade_exposure(exposure(), WINDOW, history(run(installs=None)))
        assert graded.grade is Grade.LIKELY
        assert any("could not verify" in e for e in graded.evidence)


class TestLikely:
    def test_run_on_exposing_commit_after_the_artifact_was_pulled(self):
        # The commit still pinned 5.6.1, but by then npm had removed it: the
        # install may have failed, so this cannot be CONFIRMED.
        late = datetime(2025, 11, 27, 12, tzinfo=timezone.utc)
        graded = grade_exposure(exposure(), WINDOW, history(run(at=late)))
        assert graded.grade is Grade.LIKELY
        assert any("no longer live" in e for e in graded.evidence)

    def test_runs_in_window_on_other_commits(self):
        graded = grade_exposure(exposure(), WINDOW, history(run(sha=OTHER)))
        assert graded.grade is Grade.LIKELY
        assert any("other commits" in e for e in graded.evidence)


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

    def test_run_after_remediation_does_not_confirm(self):
        exp = exposure(until=datetime(2025, 11, 25, 12, tzinfo=timezone.utc))
        after = datetime(2025, 11, 26, tzinfo=timezone.utc)  # in window, after the fix
        graded = grade_exposure(exp, WINDOW, history(run(at=after)))
        assert graded.grade is Grade.LIKELY  # on the commit, but outside the pin's life

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
        # One exposure has a run on its own commit (CONFIRMED); the other only
        # coincides in time (LIKELY). The repo is graded by the strongest.
        graded = grade_finding(
            self._finding(exposure(), exposure(commit=OTHER)), WINDOW, history(run())
        )
        assert {g.grade for g in graded.graded} == {Grade.CONFIRMED, Grade.LIKELY}
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

    def test_expired_records_add_a_finding_level_warning(self):
        recent = RunHistory(records=(), oldest_available=datetime(2026, 8, 1, tzinfo=timezone.utc),
                            source="gh")
        graded = grade_finding(self._finding(exposure()), WINDOW, recent)
        assert any("absence of a run is not absence of an install" in w
                   for w in graded.warnings)

    def test_warning_is_not_repeated_per_exposure(self):
        recent = RunHistory(records=(), oldest_available=datetime(2026, 8, 1, tzinfo=timezone.utc),
                            source="gh")
        graded = grade_finding(
            self._finding(exposure(), exposure(commit=OTHER)), WINDOW, recent
        )
        assert sum("absence of a run" in w for w in graded.warnings) == 1


class TestRunHistoryHorizon:
    def test_covers_is_false_when_horizon_unknown(self):
        assert not RunHistory().covers(datetime(2025, 11, 25, tzinfo=timezone.utc))

    def test_covers_boundary_is_inclusive(self):
        moment = datetime(2025, 11, 25, tzinfo=timezone.utc)
        assert RunHistory(oldest_available=moment).covers(moment)
        assert not RunHistory(oldest_available=moment + timedelta(seconds=1)).covers(moment)
