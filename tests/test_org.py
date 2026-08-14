"""Tests for the organization scan and the rotation list it produces.

The rotation list is the deliverable, so these tests assert what a responder
would act on: which credentials appear, why, and when the report refuses to
claim an all-clear.
"""
import json
import os
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from html import escape
from pathlib import Path

import pytest

from deptrail.grading import Grade, RunHistory, RunRecord
from deptrail.history import Verdict
from deptrail.ioc import parse_advisory
from deptrail.org import render_report, scan_organization
from deptrail.rotation import Scope, secrets_in_workflow

WINDOW = {"start": "2025-11-24T00:00:00+00:00", "end": "2025-11-26T23:59:59+00:00"}
ADVISORY = {
    "schema_version": 1, "id": "GHSA-test", "name": "Test incident",
    "ecosystem": "npm", "coverage": "complete", "window": WINDOW,
    "packages": [{"name": "chalk", "versions": ["5.6.1"],
                  "sources": ["https://example.test/a"]}],
    "sources": ["https://example.test/a"],
}
CI_WORKFLOW = """
name: CI
on: [push]
jobs:
  test:
    steps:
      - run: npm ci
      - run: deploy
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
          NPM: ${{ secrets.NPM_TOKEN }}
"""


def git(repo: Path, *args, date=None):
    env = dict(os.environ)
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
                    *args], check=True, capture_output=True, env=env)


def lock(chalk: str | None) -> str:
    packages = {"": {"dependencies": {"chalk": "^5.6.0"}}}
    if chalk:
        packages["node_modules/chalk"] = {"version": chalk}
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages})


def make_repo(tmp_path: Path, name: str, states, workflow: str | None = CI_WORKFLOW) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    if workflow:
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(workflow)
    for date, version in states:
        (repo / "package-lock.json").write_text(lock(version))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date=date)
    return repo


def head(repo: Path) -> str:
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()


def exposing_commit(repo: Path) -> str:
    """The commit that introduced the malicious version."""
    out = subprocess.run(
        ["git", "-C", str(repo), "log", "--format=%H", "--", "package-lock.json"],
        check=True, capture_output=True, text=True).stdout.split()
    for sha in out:
        body = subprocess.run(["git", "-C", str(repo), "show", f"{sha}:package-lock.json"],
                              check=True, capture_output=True, text=True).stdout
        if "5.6.1" in body:
            return sha
    raise AssertionError("no exposing commit")


def runs_with(sha: str, *, installs=True, event="push",
              at=datetime(2025, 11, 25, 12, tzinfo=timezone.utc)):
    def provider(path: Path, name: str) -> RunHistory:
        return RunHistory(
            records=(RunRecord(run_id="99", head_sha=sha, started_at=at, workflow="CI",
                               installs_dependencies=installs, event=event,
                               workflow_path=".github/workflows/ci.yml"),),
            oldest_available=datetime(2025, 11, 1, tzinfo=timezone.utc), source="test",
        )
    return provider


def no_runs(path: Path, name: str) -> RunHistory:
    return RunHistory(oldest_available=datetime(2025, 11, 1, tzinfo=timezone.utc),
                      source="test")


def secrets_provider(path: Path, name: str) -> tuple[str, ...]:
    return ("AWS_KEY", "DEPLOY_TOKEN", "NPM_TOKEN")


@pytest.fixture
def plan():
    return parse_advisory(json.dumps(ADVISORY)).plan()


class TestRotationScope:
    def test_confirmed_run_narrows_to_that_workflow_secrets(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [
            ("2025-11-20T10:00:00+00:00", "5.6.0"),
            ("2025-11-25T10:00:00+00:00", "5.6.1"),
        ])
        report = scan_organization([("api", repo)], plan,
                                   runs=runs_with(exposing_commit(repo)),
                                   secrets=secrets_provider)
        assert report.worst_grade is Grade.CONFIRMED
        items = report.rotation_items
        # AWS_KEY exists in the repo but that workflow cannot see it.
        assert {i.secret for i in items} == {"DEPLOY_TOKEN", "NPM_TOKEN"}
        assert all(i.scope is Scope.WORKFLOW for i in items)
        assert all(i.run_ids == ("99",) for i in items)

    def test_no_run_implicated_falls_back_to_developer_scope(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        report = scan_organization([("api", repo)], plan, runs=no_runs,
                                   secrets=secrets_provider)
        items = report.rotation_items
        assert {i.scope for i in items} == {Scope.DEVELOPER}
        assert {i.secret for i in items} == {"AWS_KEY", "DEPLOY_TOKEN", "NPM_TOKEN"}
        # The reason must not claim the developer held the Actions secrets, only
        # that the install happened outside CI and those values may also be local.
        assert any("outside CI" in i.reason for i in items)
        assert any("investigate that machine" in i.reason for i in items)

    def test_secrets_inherit_cannot_be_narrowed(self, tmp_path, plan):
        workflow = "name: CI\non: [push]\njobs:\n  call:\n    secrets: inherit\n    steps:\n      - run: npm ci\n"
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=workflow)
        report = scan_organization([("api", repo)], plan,
                                   runs=runs_with(exposing_commit(repo)),
                                   secrets=secrets_provider)
        items = report.rotation_items
        assert {i.scope for i in items} == {Scope.REPO_WIDE}
        assert any("secrets: inherit" in i.reason for i in items)

    def test_workflow_with_no_secrets_rotates_nothing(self, tmp_path, plan):
        workflow = "name: CI\non: [push]\njobs:\n  test:\n    steps:\n      - run: npm ci\n"
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=workflow)
        report = scan_organization([("api", repo)], plan,
                                   runs=runs_with(exposing_commit(repo)),
                                   secrets=secrets_provider)
        assert report.worst_grade is Grade.CONFIRMED
        assert report.rotation_items == ()

    def test_secret_names_only_never_values(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        names, scope, _ = secrets_in_workflow(repo, exposing_commit(repo),
                                              ".github/workflows/ci.yml")
        assert names == ("DEPLOY_TOKEN", "NPM_TOKEN") and scope is Scope.WORKFLOW


class TestOrgAggregation:
    def test_clean_repos_stay_off_the_list(self, tmp_path, plan):
        exposed = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        clean = make_repo(tmp_path, "web", [("2025-11-25T10:00:00+00:00", "5.6.0")])
        report = scan_organization([("api", exposed), ("web", clean)], plan,
                                  runs=runs_with(exposing_commit(exposed)),
                                  secrets=secrets_provider)
        assert report.exposed_repos == ("api",)
        assert {i.repo for i in report.rotation_items} == {"api"}
        assert report.repos_scanned == 2

    def test_timeline_is_ordered_across_repos(self, tmp_path, plan):
        early = make_repo(tmp_path, "early", [("2025-11-24T09:00:00+00:00", "5.6.1")])
        late = make_repo(tmp_path, "late", [("2025-11-26T09:00:00+00:00", "5.6.1")])
        report = scan_organization([("late", late), ("early", early)], plan,
                                  runs=no_runs)
        assert [e.repo for e in report.timeline] == ["early", "late"]

    def test_failed_repo_is_reported_and_blocks_all_clear(self, tmp_path, plan):
        missing = tmp_path / "gone"
        missing.mkdir()
        report = scan_organization([("gone", missing)], plan, runs=no_runs)
        assert report.errors and "not a git repository" in report.errors[0]
        assert not report.proves_absence

    def test_crash_in_one_repo_does_not_lose_the_others(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        broken = make_repo(tmp_path, "broken", [("2025-11-25T10:00:00+00:00", "5.6.1")])

        def flaky(path: Path, name: str) -> RunHistory:
            if name == "broken":
                raise RuntimeError("gh unavailable")
            return runs_with(exposing_commit(repo))(path, name)

        report = scan_organization([("broken", broken), ("api", repo)], plan, runs=flaky)
        assert any("gh unavailable" in e for e in report.errors)
        # Losing the CI evidence must not lose the exposure git already proved.
        assert report.exposed_repos == ("api", "broken")
        broken_grades = {e.grade for e in report.timeline if e.repo == "broken"}
        assert broken_grades == {Grade.POSSIBLE}
        assert not report.proves_absence

    def test_partial_advisory_never_proves_absence(self, tmp_path):
        partial = dict(ADVISORY, coverage="partial")
        plan = parse_advisory(json.dumps(partial)).plan()
        clean = make_repo(tmp_path, "web", [("2025-11-25T10:00:00+00:00", "5.6.0")])
        report = scan_organization([("web", clean)], plan, runs=no_runs)
        assert report.worst_grade is Grade.NO_EVIDENCE
        assert not report.proves_absence
        assert any("partial coverage" in n for n in report.notes)

    def test_unreadable_history_is_not_cleared_and_names_nothing(self, tmp_path, plan):
        origin = make_repo(tmp_path, "origin", [
            ("2025-11-25T10:00:00+00:00", "5.6.1"),
            ("2025-11-28T10:00:00+00:00", "5.6.2"),
        ])
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}",
                        str(shallow)], check=True, capture_output=True)
        report = scan_organization([("shallow", shallow)], plan, runs=no_runs,
                                  secrets=secrets_provider)
        # A repository we could not read is not cleared — and it is not turned into a
        # credential list either. The clone is shallow, nothing was found in what is
        # visible, and no evidence points at any secret, so the honest answer is
        # "could not prove absence" and not "rotate everything you own" (#20).
        assert not report.proves_absence
        assert report.worst_grade is Grade.POSSIBLE
        assert report.incomplete and "shallow" in report.incomplete[0]
        assert report.rotation_items == ()
        assert report.rotation_required is False


class TestRendering:
    def test_report_shows_timeline_rotation_and_caveats(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        report = scan_organization([("api", repo)], plan,
                                  runs=runs_with(exposing_commit(repo)),
                                  secrets=secrets_provider)
        text = render_report(report)
        assert "CONFIRMED" in text and "api" in text
        assert "DEPLOY_TOKEN" in text and "AWS_KEY" not in text
        assert "rotate (2 credential(s))" in text

    def test_report_states_when_it_cannot_prove_absence(self, tmp_path, plan):
        missing = tmp_path / "gone"
        missing.mkdir()
        text = render_report(scan_organization([("gone", missing)], plan, runs=no_runs))
        assert "cannot prove absence" in text and "could not scan" in text


class TestFixtureLockfiles:
    """E7: this project's own fixtures were flagged; noise must not reach rotation."""

    @pytest.mark.parametrize("path,installed", [
        ("package-lock.json", True),
        ("packages/api/package-lock.json", True),
        ("tests/fixtures/v3/package-lock.json", False),
        ("examples/demo/package-lock.json", False),
        ("spec/testdata/package-lock.json", False),
        ("vendor/thing/package-lock.json", False),
        ("src/attestation/package-lock.json", True),
    ])
    def test_classification(self, path, installed):
        from deptrail.org import is_probably_installed
        assert is_probably_installed(path) is installed

    def _fixture_repo(self, tmp_path):
        repo = tmp_path / "toolrepo"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(CI_WORKFLOW)
        (repo / "tests/fixtures").mkdir(parents=True)
        (repo / "tests/fixtures/package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "fixtures", date="2025-11-25T10:00:00+00:00")
        return repo

    def test_fixture_exposure_is_visible_but_not_rotated(self, tmp_path, plan):
        repo = self._fixture_repo(tmp_path)
        report = scan_organization([("toolrepo", repo)], plan,
                                  runs=runs_with(head(repo)), secrets=secrets_provider)
        assert report.set_aside, "the finding must stay visible"
        assert report.rotation_items == ()
        assert report.exposed_repos == ()
        assert report.worst_grade is Grade.NO_EVIDENCE

    def test_report_explains_what_was_set_aside(self, tmp_path, plan):
        repo = self._fixture_repo(tmp_path)
        text = render_report(scan_organization([("toolrepo", repo)], plan,
                                              runs=runs_with(head(repo))))
        assert "set aside (1)" in text and "tests/fixtures/package-lock.json" in text
        assert "no exposure found in an installed tree" in text


class TestUnreadableTrees:
    """#16: a repository we could not read must not be reported as clean, and must
    not be reported as a reason to rotate either."""

    def _yarn_repo(self, tmp_path, name="mobile", where="yarn.lock"):
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(CI_WORKFLOW)
        target = repo / where
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('"chalk@^5.6.0":\n  version "5.6.1"\n')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "lock", date="2025-11-25T10:00:00+00:00")
        return repo

    def test_scan_refuses_to_prove_absence(self, tmp_path, plan):
        repo = self._yarn_repo(tmp_path)
        report = scan_organization([("mobile", repo)], plan,
                                   runs=no_runs, secrets=secrets_provider)
        assert not report.proves_absence
        assert report.unread and "Yarn" in report.unread[0]

    def test_no_credential_is_listed_for_a_tree_we_never_read(self, tmp_path, plan):
        # Grading it POSSIBLE would put every Yarn repository's whole secret store
        # on a rotation list, which is a false alarm, not caution.
        repo = self._yarn_repo(tmp_path)
        report = scan_organization([("mobile", repo)], plan,
                                   runs=no_runs, secrets=secrets_provider)
        assert report.rotation_items == ()
        assert report.unnamed_rotations == ()
        assert report.rotation_required is False
        assert report.worst_grade is Grade.NO_EVIDENCE

    def test_report_says_which_tree_was_not_judged(self, tmp_path, plan):
        repo = self._yarn_repo(tmp_path)
        text = render_report(scan_organization([("mobile", repo)], plan, runs=no_runs))
        assert "not judged" in text
        assert "yarn.lock" in text
        assert "no exposure found in what could be read" in text
        assert "cannot prove absence" in text
        # The reason belongs under its own heading, printed once.
        assert text.count("Yarn lockfiles are not parsed yet") == 1

    def test_a_workflow_naming_the_directory_beats_the_heuristic(self, tmp_path, plan):
        # An application that really lives under examples/ must not be filed away
        # as sample data: the repository would be cleared on a directory name.
        repo = tmp_path / "deployed-example"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(
            CI_WORKFLOW.replace("- run: npm ci",
                                "- run: yarn --frozen-lockfile\n        "
                                "working-directory: examples/production")
        )
        (repo / "examples/production").mkdir(parents=True)
        (repo / "examples/production/yarn.lock").write_text(
            '"chalk@^5.6.0":\n  version "5.6.1"\n')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deploy the example",
            date="2025-11-25T10:00:00+00:00")
        report = scan_organization([("deployed-example", repo)], plan, runs=no_runs)
        assert report.unread, "the workflow names this directory, so it is deployed"
        assert not report.proves_absence

    def test_fixture_yarn_lockfile_does_not_cost_the_verdict(self, tmp_path, plan):
        # A tooling repo that keeps a Yarn fixture is not a repo with an unread
        # dependency tree; treating it as one would deny an all-clear to projects
        # that merely test against other package managers.
        repo = self._yarn_repo(tmp_path, name="toolrepo",
                               where="tests/fixtures/yarn/yarn.lock")
        report = scan_organization([("toolrepo", repo)], plan, runs=no_runs)
        assert report.proves_absence
        assert report.unread == []
        assert any("set aside" in note for note in report.notes), \
            "the set-aside tree must stay visible"

    def test_an_exposed_repo_keeps_its_rotation_list_and_gains_the_caveat(self, tmp_path,
                                                                         plan):
        repo = make_repo(tmp_path, "api", [
            ("2025-11-25T10:00:00+00:00", "5.6.1"),
        ])
        (repo / "mobile").mkdir()
        (repo / "mobile/yarn.lock").write_text('"chalk@^5.6.0":\n  version "5.6.1"\n')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "mobile", date="2025-11-25T11:00:00+00:00")
        report = scan_organization([("api", repo)], plan,
                                   runs=runs_with(exposing_commit(repo)),
                                   secrets=secrets_provider)
        assert report.rotation_items, "the npm tree's exposure still rotates"
        assert report.unread and "mobile/yarn.lock" in report.unread[0]
        assert not report.proves_absence


class TestWideningNeedsSomethingToWiden:
    """#20: a lost snapshot broadens the scope of what *was* found, and names nothing
    when nothing was found. Reverting the gate to `if finding.warnings:` passed the
    whole suite before these existed."""

    def _unreadable(self, repo, path, date):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{ not json")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"broken {path}", date=date)

    def test_a_lost_snapshot_alone_names_no_credential(self, tmp_path, plan):
        repo = tmp_path / "broken"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(CI_WORKFLOW)
        self._unreadable(repo, "package-lock.json", "2025-11-25T10:00:00+00:00")
        report = scan_organization([("broken", repo)], plan, runs=no_runs,
                                   secrets=secrets_provider)
        assert not report.proves_absence, "an unreadable lockfile is not an all-clear"
        assert report.worst_grade is Grade.POSSIBLE
        assert report.rotation_items == ()
        assert report.rotation_required is False

    def test_a_lost_snapshot_alone_names_nothing_even_unnamed(self, tmp_path, plan):
        # Without a secrets provider the old gate produced an `unnamed` entry, which
        # `rotation_required` counts — so exit 1 came back by another door.
        repo = tmp_path / "broken2"
        repo.mkdir()
        git(repo, "init", "-q")
        self._unreadable(repo, "package-lock.json", "2025-11-25T10:00:00+00:00")
        report = scan_organization([("broken2", repo)], plan, runs=no_runs)
        assert report.unnamed_rotations == ()
        assert report.rotation_required is False
        assert not report.proves_absence

    def test_only_a_set_aside_exposure_plus_a_lost_snapshot_names_nothing(self, tmp_path,
                                                                         plan):
        # `kept` is empty because the exposure is a fixture, so there is still nothing
        # to widen — the gate must look at what survived, not at what was found.
        repo = tmp_path / "fixtures-only"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "tests/fixtures").mkdir(parents=True)
        (repo / "tests/fixtures/package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "fixture", date="2025-11-25T10:00:00+00:00")
        self._unreadable(repo, "svc/package-lock.json", "2025-11-25T11:00:00+00:00")
        report = scan_organization([("fixtures-only", repo)], plan, runs=no_runs,
                                   secrets=secrets_provider)
        assert report.set_aside, "the fixture finding stays visible"
        assert report.rotation_items == ()
        assert not report.proves_absence

    def test_a_real_exposure_plus_a_lost_snapshot_still_widens(self, tmp_path, plan):
        # The other direction, which E14 established and this must not undo.
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        self._unreadable(repo, "svc/package-lock.json", "2025-11-25T11:00:00+00:00")
        report = scan_organization([("api", repo)], plan,
                                   runs=runs_with(exposing_commit(repo)),
                                   secrets=secrets_provider)
        secrets = {i.secret for i in report.rotation_items}
        assert "AWS_KEY" in secrets, secrets


class TestTheFindingAndTheReportMustAgree:
    """Two places derive the same repository's verdict from the same data. When they
    disagreed, only a separate check in `proves_absence` kept the exit code right, and
    a consumer reading `OrgReport.findings` saw CLEAN for a clone that was truncated."""

    def _shallow(self, tmp_path, plan):
        origin = make_repo(tmp_path, "origin", [("2025-11-25T10:00:00+00:00", "5.6.0")])
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}",
                        str(shallow)], check=True, capture_output=True)
        return scan_organization([("shallow", shallow)], plan, runs=no_runs)

    def test_the_kept_finding_carries_the_truncation(self, tmp_path, plan):
        report = self._shallow(tmp_path, plan)
        finding = report.findings[0]
        assert finding.incomplete, "the reason must travel with the finding"
        assert finding.verdict is Verdict.INDETERMINATE, (
            "the finding the report keeps is the one proves_absence answers to"
        )
        assert not report.proves_absence

    def test_an_incomplete_only_repo_is_not_asked_for_its_secret_names(self, tmp_path,
                                                                      plan):
        # Listing secrets needs an admin-scoped token. Asking for a repository whose
        # rotation list is going to be empty spends that permission for nothing, and
        # reports the refusal as "could not scan".
        asked = []

        def recording_secrets(path, name):
            asked.append(name)
            return ("AWS_KEY",)

        origin = make_repo(tmp_path, "origin", [("2025-11-25T10:00:00+00:00", "5.6.0")])
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}",
                        str(shallow)], check=True, capture_output=True)
        report = scan_organization([("shallow", shallow)], plan, runs=no_runs,
                                   secrets=recording_secrets)
        assert asked == [], "nothing was found, so no credential list is being built"
        assert report.rotation_items == ()
        assert not report.proves_absence


class TestAnExposureMustNotMaskLostEvidence:
    """Review of #16: an exposure wins the aggregate verdict, and both the
    completeness claim and the rotation fallback were keyed on that verdict — so a
    second, unreadable tree in the same repository vanished from both."""

    def _mixed(self, tmp_path):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        (repo / "service").mkdir()
        (repo / "service/package-lock.json").write_text("{ not json")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "second tree", date="2025-11-25T11:00:00+00:00")
        return repo

    def test_completeness_is_not_claimed(self, tmp_path, plan):
        repo = self._mixed(tmp_path)
        report = scan_organization([("api", repo)], plan,
                                   runs=runs_with(exposing_commit(repo)),
                                   secrets=secrets_provider)
        assert report.rotation_items, "the readable tree's exposure still rotates"
        assert not report.proves_absence, \
            "one tree was unreadable, so the scan saw less than everything"

    def test_the_unreadable_tree_widens_the_rotation_list(self, tmp_path, plan):
        # The confirmed workflow names DEPLOY_TOKEN and NPM_TOKEN; AWS_KEY is only
        # reachable through the repo-wide fallback, which the verdict gate dropped.
        repo = self._mixed(tmp_path)
        report = scan_organization([("api", repo)], plan,
                                   runs=runs_with(exposing_commit(repo)),
                                   secrets=secrets_provider)
        secrets = {i.secret for i in report.rotation_items}
        assert "AWS_KEY" in secrets, secrets
        assert {"DEPLOY_TOKEN", "NPM_TOKEN"} <= secrets
        # The narrow evidence keeps its stronger grade after the merge.
        by_secret = {i.secret: i.grade for i in report.rotation_items}
        assert by_secret["NPM_TOKEN"] is Grade.CONFIRMED
        assert by_secret["AWS_KEY"] is Grade.POSSIBLE


class TestMultipleWorkflows:
    """One push fires several workflows; each one's secrets were in scope."""

    def _two_workflow_repo(self, tmp_path, second: str):
        repo = tmp_path / "multi"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(CI_WORKFLOW)
        (repo / ".github/workflows/deploy.yml").write_text(second)
        (repo / "package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        return repo

    def _runs_for(self, sha, paths):
        def provider(path: Path, name: str) -> RunHistory:
            return RunHistory(
                records=tuple(
                    RunRecord(run_id=str(i), head_sha=sha,
                              started_at=datetime(2025, 11, 25, 12, i, tzinfo=timezone.utc),
                              workflow=f"W{i}", installs_dependencies=True,
                              event="push", workflow_path=p)
                    for i, p in enumerate(paths, start=1)
                ),
                oldest_available=datetime(2025, 11, 1, tzinfo=timezone.utc), source="test",
            )
        return provider

    def test_secrets_of_every_implicated_workflow_are_rotated(self, tmp_path, plan):
        deploy = ("name: Deploy\non: [push]\njobs:\n  ship:\n    steps:\n"
                  "      - run: npm ci\n      - run: ship\n        env:\n"
                  "          KEY: ${{ secrets.AWS_KEY }}\n")
        repo = self._two_workflow_repo(tmp_path, deploy)
        report = scan_organization(
            [("multi", repo)], plan,
            runs=self._runs_for(head(repo), (".github/workflows/ci.yml",
                                             ".github/workflows/deploy.yml")),
            secrets=secrets_provider,
        )
        assert {i.secret for i in report.rotation_items} == {
            "DEPLOY_TOKEN", "NPM_TOKEN", "AWS_KEY"
        }

    def test_a_secretless_workflow_does_not_empty_the_list(self, tmp_path, plan):
        # ci.yml here reads no secrets; deploy.yml does. Narrowing to the first
        # implicated workflow alone would report nothing to rotate.
        plain = "name: CI\non: [push]\njobs:\n  test:\n    steps:\n      - run: npm ci\n"
        repo = tmp_path / "multi2"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(plain)
        (repo / ".github/workflows/deploy.yml").write_text(
            "name: Deploy\non: [push]\njobs:\n  ship:\n    steps:\n      - run: npm ci\n"
            "      - run: ship\n        env:\n          KEY: ${{ secrets.AWS_KEY }}\n"
        )
        (repo / "package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        report = scan_organization(
            [("multi2", repo)], plan,
            runs=self._runs_for(head(repo), (".github/workflows/ci.yml",
                                             ".github/workflows/deploy.yml")),
            secrets=secrets_provider,
        )
        assert report.worst_grade is Grade.CONFIRMED
        assert {i.secret for i in report.rotation_items} == {"AWS_KEY"}


class TestSecretWildcards:
    @pytest.mark.parametrize("body,marker", [
        ("      - run: echo ${{ toJSON(secrets) }}\n", "whole `secrets` context"),
        ("      - run: echo ${{ secrets[format('T_{0}', matrix.e)] }}\n", "at runtime"),
        ("    secrets: inherit\n", "secrets: inherit"),
    ])
    def test_wildcards_cannot_be_narrowed(self, tmp_path, plan, body, marker):
        workflow = f"name: CI\non: [push]\njobs:\n  test:\n    steps:\n      - run: npm ci\n{body}"
        repo = make_repo(tmp_path, "wild", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=workflow)
        report = scan_organization([("wild", repo)], plan,
                                  runs=runs_with(head(repo)), secrets=secrets_provider)
        items = report.rotation_items
        assert items, "a job holding every secret must not report nothing to rotate"
        assert {i.scope for i in items} == {Scope.REPO_WIDE}
        assert any(marker in i.reason for i in items)


class TestDeduplicationAndHonesty:
    def test_one_credential_appears_once_across_packages(self, tmp_path):
        two = dict(ADVISORY, packages=[
            {"name": "chalk", "versions": ["5.6.1"], "sources": ["https://a.test"]},
            {"name": "debug", "versions": ["4.4.2"], "sources": ["https://a.test"]},
        ])
        plan = parse_advisory(json.dumps(two)).plan()
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        report = scan_organization([("api", repo)], plan,
                                  runs=runs_with(exposing_commit(repo)),
                                  secrets=secrets_provider)
        secrets_listed = [i.secret for i in report.rotation_items]
        assert sorted(secrets_listed) == ["DEPLOY_TOKEN", "NPM_TOKEN"]
        assert len(secrets_listed) == len(set(secrets_listed))

    def test_unlistable_secrets_produce_a_note_not_a_fake_credential(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        report = scan_organization([("api", repo)], plan, runs=no_runs)
        assert report.rotation_items == ()
        assert any("could not be listed" in n for n in report.rotation_notes)
        # The list must not read as an all-clear when nothing could be named.
        assert "rotate: nothing" not in render_report(report)

    def test_repo_with_no_secrets_says_so(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        report = scan_organization([("api", repo)], plan, runs=no_runs,
                                  secrets=lambda path, name: ())
        assert report.rotation_items == ()
        assert any("holds no secrets" in n for n in report.rotation_notes)

    def test_github_token_is_context_not_an_action(self, tmp_path, plan):
        workflow = ("name: CI\non: [push]\njobs:\n  test:\n    steps:\n      - run: npm ci\n"
                    "      - run: gh pr list\n        env:\n"
                    "          GH: ${{ secrets.GITHUB_TOKEN }}\n"
                    "          KEY: ${{ secrets.AWS_KEY }}\n")
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=workflow)
        report = scan_organization([("api", repo)], plan,
                                  runs=runs_with(head(repo)), secrets=secrets_provider)
        assert {i.secret for i in report.rotation_items} == {"AWS_KEY"}
        assert any("expires with its run" in n for n in report.rotation_notes)

    def test_fixture_exposure_does_not_silence_unreadable_history(self, tmp_path, plan):
        origin = tmp_path / "origin"
        origin.mkdir()
        git(origin, "init", "-q")
        (origin / "tests/fixtures").mkdir(parents=True)
        (origin / "tests/fixtures/package-lock.json").write_text(lock("5.6.1"))
        git(origin, "add", "-A")
        git(origin, "commit", "-qm", "fixtures", date="2025-11-25T10:00:00+00:00")
        (origin / "README.md").write_text("x")
        git(origin, "add", "-A")
        git(origin, "commit", "-qm", "more", date="2025-11-26T10:00:00+00:00")
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}",
                        str(shallow)], check=True, capture_output=True)
        report = scan_organization([("shallow", shallow)], plan, runs=no_runs,
                                  secrets=secrets_provider)
        # The fixture exposure is set aside, so nothing was found in an installed
        # tree; the clone is shallow, so absence cannot be claimed either. Both
        # statements have to survive together.
        assert not report.proves_absence
        assert report.set_aside, "the fixture finding stays visible"
        assert report.rotation_items == ()

    def test_secrets_provider_failure_keeps_the_findings(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])

        def broken(path: Path, name: str) -> tuple[str, ...]:
            raise RuntimeError("gh auth expired")

        report = scan_organization([("api", repo)], plan,
                                  runs=runs_with(exposing_commit(repo)), secrets=broken)
        assert report.exposed_repos == ("api",)
        assert any("gh auth expired" in e for e in report.errors)
        assert not report.proves_absence

    def test_report_cites_package_grade_and_runs(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        text = render_report(scan_organization(
            [("api", repo)], plan, runs=runs_with(exposing_commit(repo)),
            secrets=secrets_provider,
        ))
        assert "chalk@5.6.1" in text
        assert "run 99" in text and "[CONFIRMED  ]" in text


class TestEvidenceBeatsPathHeuristic:
    """codex: a real app can live under examples/; a root install is not proof
    that a fixture lockfile was installed."""

    def _repo(self, tmp_path, lockfile_dir: str, workflow: str):
        repo = tmp_path / "app"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(workflow)
        target = repo / lockfile_dir
        target.mkdir(parents=True, exist_ok=True)
        (target / "package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        return repo

    def test_deployed_app_under_examples_is_not_filed_away(self, tmp_path, plan):
        workflow = ("name: CI\non: [push]\njobs:\n  ship:\n"
                    "    defaults:\n      run:\n"
                    "        working-directory: examples/production\n"
                    "    steps:\n      - run: npm ci\n      - run: deploy\n"
                    "        env:\n          KEY: ${{ secrets.AWS_KEY }}\n")
        repo = self._repo(tmp_path, "examples/production", workflow)
        report = scan_organization([("app", repo)], plan, runs=runs_with(head(repo)),
                                  secrets=secrets_provider)
        assert report.exposed_repos == ("app",)
        assert report.set_aside == ()
        assert {i.secret for i in report.rotation_items} == {"AWS_KEY"}

    def test_root_install_is_not_credited_with_a_fixture_tree(self, tmp_path, plan):
        repo = self._repo(tmp_path, "tests/fixtures", CI_WORKFLOW)
        report = scan_organization([("app", repo)], plan, runs=runs_with(head(repo)),
                                  secrets=secrets_provider)
        assert report.set_aside and report.rotation_items == ()


class TestCodexRegressions:
    """Each test reproduces a wrong result codex found on 86dc828."""

    def test_one_unknown_workflow_path_blocks_narrowing(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        sha = exposing_commit(repo)

        def mixed(path: Path, name: str) -> RunHistory:
            at = datetime(2025, 11, 25, 12, tzinfo=timezone.utc)
            return RunHistory(
                records=(
                    RunRecord(run_id="1", head_sha=sha, started_at=at, workflow="CI",
                              installs_dependencies=True, event="push",
                              workflow_path=".github/workflows/ci.yml"),
                    RunRecord(run_id="2", head_sha=sha, started_at=at, workflow="?",
                              installs_dependencies=True, event="push",
                              workflow_path=None),
                ),
                oldest_available=datetime(2025, 11, 1, tzinfo=timezone.utc), source="t",
            )

        report = scan_organization([("api", repo)], plan, runs=mixed,
                                  secrets=secrets_provider)
        items = report.rotation_items
        assert {i.scope for i in items} == {Scope.REPO_WIDE}
        assert "AWS_KEY" in {i.secret for i in items}

    def test_reusable_workflow_secrets_are_followed(self, tmp_path, plan):
        caller = ("name: CI\non: [push]\njobs:\n  build:\n    steps:\n      - run: npm ci\n"
                  "  ship:\n    uses: ./.github/workflows/deploy.yml\n")
        callee = ("name: Deploy\non:\n  workflow_call:\njobs:\n  go:\n"
                  "    environment: production\n    steps:\n      - run: ship\n"
                  "        env:\n          T: ${{ secrets.PROD_TOKEN }}\n")
        repo = tmp_path / "reuse"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text(caller)
        (repo / ".github/workflows/deploy.yml").write_text(callee)
        (repo / "package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        report = scan_organization([("reuse", repo)], plan, runs=runs_with(head(repo)),
                                  secrets=lambda p, n: ("PROD_TOKEN", "OTHER"))
        assert {i.secret for i in report.rotation_items} == {"PROD_TOKEN"}

    def test_remote_reusable_workflow_cannot_be_narrowed(self, tmp_path, plan):
        workflow = ("name: CI\non: [push]\njobs:\n  build:\n    steps:\n      - run: npm ci\n"
                    "  ship:\n    uses: other-org/shared/.github/workflows/deploy.yml@v1\n")
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=workflow)
        report = scan_organization([("api", repo)], plan, runs=runs_with(head(repo)),
                                  secrets=secrets_provider)
        assert {i.scope for i in report.rotation_items} == {Scope.REPO_WIDE}

    def test_comments_and_plain_strings_are_not_references(self, tmp_path, plan):
        workflow = ("name: CI\non: [push]\njobs:\n  test:\n    steps:\n      - run: npm ci\n"
                    "      # - run: echo ${{ secrets.RETIRED }}\n"
                    "      - run: echo \"secrets.NOT_AN_EXPRESSION\"\n"
                    "      - run: use\n        env:\n          K: ${{ secrets.REAL_KEY }}\n")
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=workflow)
        names, scope, _ = secrets_in_workflow(repo, head(repo), ".github/workflows/ci.yml")
        assert names == ("REAL_KEY",) and scope is Scope.WORKFLOW

    def test_post_window_run_does_not_erase_the_local_install(self, tmp_path, plan):
        # A secretless workflow ran after the artifact was pulled. That is not
        # evidence CI installed it, so the local install must still be listed.
        plain = "name: CI\non: [push]\njobs:\n  t:\n    steps:\n      - run: npm ci\n"
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=plain)
        after = datetime(2025, 12, 20, tzinfo=timezone.utc)
        report = scan_organization(
            [("api", repo)], plan,
            runs=runs_with(exposing_commit(repo), at=after), secrets=secrets_provider,
        )
        items = report.rotation_items
        assert {i.scope for i in items} == {Scope.DEVELOPER}
        assert {i.secret for i in items} == {"AWS_KEY", "DEPLOY_TOKEN", "NPM_TOKEN"}

    def test_ci_coverage_note_does_not_make_a_repo_indeterminate(self, tmp_path, plan):
        # A thin CI record is not an unreadable history: a clean repo stays clean.
        clean = make_repo(tmp_path, "web", [("2025-11-25T10:00:00+00:00", "5.6.0")])

        def unknown_horizon(path: Path, name: str) -> RunHistory:
            return RunHistory(source="no horizon")

        report = scan_organization([("web", clean)], plan, runs=unknown_horizon,
                                  secrets=secrets_provider)
        assert report.rotation_items == ()
        assert report.worst_grade is Grade.NO_EVIDENCE

    def test_merged_scope_is_order_invariant(self, tmp_path):
        from deptrail.grading import Grade as G
        from deptrail.org import OrgReport
        from deptrail.rotation import Caveat, RepoRotation, RotationItem

        dev = RotationItem(repo="api", secret="K", scope=Scope.DEVELOPER, grade=G.POSSIBLE,
                           causes=(Caveat("local"),))
        wide = RotationItem(repo="api", secret="K", scope=Scope.REPO_WIDE, grade=G.POSSIBLE,
                            causes=(Caveat("unreadable"),), run_ids=("9",))
        first = OrgReport(advisory_id="x", advisory_name="x",
                          rotations=[RepoRotation(repo="api", items=[dev, wide])])
        second = OrgReport(advisory_id="x", advisory_name="x",
                           rotations=[RepoRotation(repo="api", items=[wide, dev])])
        assert first.rotation_items[0].scope is second.rotation_items[0].scope is Scope.REPO_WIDE

    def test_indeterminate_repo_is_visible_in_the_header(self, tmp_path, plan):
        origin = make_repo(tmp_path, "origin", [
            ("2025-11-25T10:00:00+00:00", "5.6.1"),
            ("2025-11-28T10:00:00+00:00", "5.6.2"),
        ])
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}",
                        str(shallow)], check=True, capture_output=True)
        text = render_report(scan_organization([("shallow", shallow)], plan, runs=no_runs,
                                             secrets=secrets_provider))
        assert "worst grade POSSIBLE" in text
        assert "cannot prove absence" in text


class TestEnvironmentSecrets:
    def test_environment_is_named_because_its_secrets_are_not_listed(self, tmp_path, plan):
        workflow = ("name: CI\non: [push]\njobs:\n  ship:\n    environment: production\n"
                    "    steps:\n      - run: npm ci\n      - run: deploy\n"
                    "        env:\n          T: ${{ secrets.PROD_TOKEN }}\n")
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")],
                         workflow=workflow)
        report = scan_organization([("api", repo)], plan, runs=runs_with(head(repo)),
                                  secrets=lambda p, n: ("REPO_ONLY",))
        assert {i.secret for i in report.rotation_items} == {"PROD_TOKEN"}
        assert any("environment(s) production" in n for n in report.rotation_notes)


THREE = dict(ADVISORY, packages=[
    {"name": "chalk", "versions": ["5.6.1"], "sources": ["https://a.test"]},
    {"name": "debug", "versions": ["4.4.2"], "sources": ["https://a.test"]},
    {"name": "ansi-styles", "versions": ["6.2.2"], "sources": ["https://a.test"]},
])
PINNED = {"chalk": "5.6.1", "debug": "4.4.2", "ansi-styles": "6.2.2"}


def multi_lock(versions: dict[str, str]) -> str:
    packages = {"": {"dependencies": {n: f"^{v}" for n, v in versions.items()}}}
    for name, version in versions.items():
        packages[f"node_modules/{name}"] = {"version": version}
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages})


def make_multi_repo(tmp_path: Path, name: str) -> Path:
    """A repo that pins every package a three-package advisory names."""
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / ".github/workflows/ci.yml").write_text(CI_WORKFLOW)
    (repo / "package-lock.json").write_text(multi_lock({n: "0.0.1" for n in PINNED}))
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "deps", date="2025-11-20T10:00:00+00:00")
    (repo / "package-lock.json").write_text(multi_lock(PINNED))
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "bad", date="2025-11-25T10:00:00+00:00")
    return repo


@pytest.fixture
def three():
    return parse_advisory(json.dumps(THREE)).plan()


class TestOneSentencePerRepoNotPerPackage:
    """#30: the same paragraph was printed once per package the advisory named.

    A repository is scanned once per package, so every sentence that mentions no
    package at all was reached N times, and every sentence that mentioned a version
    differed only in that version — which no string comparison could collapse. The
    fix keeps the varying part as data; these tests hold it there.
    """

    def test_unnamed_rotation_is_one_line_naming_every_version(self, tmp_path, three):
        repo = make_multi_repo(tmp_path, "r2")
        report = scan_organization([("r2", repo)], three, runs=no_runs)
        assert len(report.unnamed_rotations) == 1, report.unnamed_rotations
        line = report.unnamed_rotations[0]
        # Collapsing must not cost the evidence: a responder checking a machine by
        # hand needs to know which versions were pinned.
        for package, version in PINNED.items():
            assert f"{package}@{version}" in line

    def test_report_has_no_repeated_line(self, tmp_path, three):
        repo = make_multi_repo(tmp_path, "r2")
        text = render_report(scan_organization([("r2", repo)], three, runs=no_runs))
        body = [line for line in text.splitlines() if line.strip()]
        assert len(body) == len(set(body)), "\n".join(body)

    def test_caveats_do_not_repeat_the_rotate_section(self, tmp_path, three):
        repo = make_multi_repo(tmp_path, "r2")
        report = scan_organization([("r2", repo)], three, runs=no_runs)
        assert report.unnamed_rotations, "the case under test needs an unnamed rotation"
        # The rotate section prints these; a dedicated section and the caveats block
        # both carrying them made a reader count the same gap twice.
        for line in report.unnamed_rotations:
            assert line not in report.caveats

    def test_the_renderers_actually_use_that_subtraction(self, tmp_path, three):
        from deptrail.report import render_html

        repo = make_multi_repo(tmp_path, "r2")
        report = scan_organization([("r2", repo)], three, runs=no_runs)
        assert report.unnamed_rotations
        # Asserting on `report.caveats` alone tests a property no renderer is obliged
        # to call: reverting render_report to its own older subtraction printed the
        # same risk twice and every test still passed. So the assertion has to be made
        # against the rendered output, where the duplication would actually be read.
        #
        # Compared as normalised words rather than as lines, because the terminal
        # renderer folds a long line and the two copies would carry different indents.
        text = " ".join(render_report(report).split())
        html = " ".join(render_html(report).split())
        for line in report.unnamed_rotations:
            sentence = " ".join(line.split())
            assert text.count(sentence) == 1, sentence
            # The HTML escapes it, so the escaped form is what to count there.
            assert html.count(escape(sentence)) == 1, sentence

    def test_merged_reason_keeps_every_version_and_the_whole_sentence(self, tmp_path,
                                                                     three):
        repo = make_multi_repo(tmp_path, "r2")
        report = scan_organization([("r2", repo)], three, runs=no_runs,
                                   secrets=lambda p, n: ("AWS_KEY",))
        items = report.rotation_items
        assert len(items) == 1
        reason = items[0].reason
        for package, version in PINNED.items():
            assert f"{package}@{version}" in reason
        # Deduplicating the clauses of joined prose used to drop the tail of every
        # sentence after the first, so the advice appeared once and the second and
        # third packages' reasons ended mid-thought at "outside CI".
        assert reason.count("investigate that machine") == 1
        assert reason.count("pinned in package-lock.json") == 1

    def test_a_repo_that_could_not_be_listed_is_shown_beside_named_credentials(
            self, tmp_path, three):
        named = make_multi_repo(tmp_path, "r2")
        unlistable = make_multi_repo(tmp_path, "web")

        def mixed(path: Path, name: str) -> tuple[str, ...]:
            if name == "web":
                raise RuntimeError("403: admin scope required")
            return ("AWS_KEY",)

        report = scan_organization([("r2", named), ("web", unlistable)], three,
                                   runs=no_runs, secrets=mixed)
        text = render_report(report)
        assert report.unnamed_repos == ("web",)
        rotate = text.split("rotate (")[1].split("\n\n")[0]
        # `elif` used to hide this block whenever another repository named a
        # credential, leaving a repo-wide risk out of the rotation section while the
        # heading counted only what could be named.
        assert "web" in rotate
        assert "1 repository to rotate broadly" in text
        assert "1 credential(s)" in text

    def test_long_line_is_folded_and_loses_no_version(self):
        from deptrail.org import BODY_WIDTH, OrgReport
        from deptrail.rotation import Caveat, RepoRotation

        subjects = tuple(f"pkg-{i:03d}@{i}.0.1" for i in range(180))
        report = OrgReport(advisory_id="x", advisory_name="x", rotations=[
            RepoRotation(repo="api", unnamed=[
                Caveat(text="pinned in package-lock.json, and no CI run was implicated "
                            "— so any install happened outside CI",
                       subjects=subjects)])])
        text = render_report(report)
        assert max(len(line) for line in text.splitlines()) <= BODY_WIDTH
        for subject in subjects:
            assert subject in text, subject


class TestCaveatMerging:
    def test_first_appearance_order_is_kept(self):
        from deptrail.rotation import Caveat, merge_caveats

        merged = merge_caveats([
            Caveat("second sentence", ("b@2",)),
            Caveat("first sentence", ("a@1",)),
            Caveat("second sentence", ("c@3",)),
            Caveat("first sentence", ("a@1",)),
        ])
        # A report that reorders itself between runs cannot be diffed against the
        # previous one, and a duplicate subject must not be listed twice.
        assert [c.text for c in merged] == ["second sentence", "first sentence"]
        assert merged[0].subjects == ("b@2", "c@3")
        assert merged[1].subjects == ("a@1",)

    def test_a_sentence_without_subjects_renders_unchanged(self):
        from deptrail.rotation import Caveat

        assert Caveat("nothing varies here").rendered == "nothing varies here"

    def test_extending_a_sentence_keeps_it_mergeable(self):
        from deptrail.rotation import Caveat, _extend, merge_caveats

        base = Caveat("history could not be read", ("a@1",))
        extended = [_extend(base, "— and secrets could not be listed"),
                    _extend(Caveat("history could not be read", ("b@2",)),
                            "— and secrets could not be listed")]
        # The suffix has to land on the text, not between the subjects and it, or two
        # packages reaching the same dead end would no longer merge.
        assert len(merge_caveats(extended)) == 1
        assert merge_caveats(extended)[0].subjects == ("a@1", "b@2")


class TestEveryRendererAgrees:
    """The text report, the HTML file and the JSON payload must say the same thing.

    Each of them used to compute "what is already shown above" itself, and each drifted:
    the JSON counted every gap twice, and the HTML kept the `elif` that hides a
    repository's repo-wide risk. The HTML file is the artifact the composite action
    forwards, so a gap there is the one a reader is most likely to meet.
    """

    @pytest.fixture
    def mixed(self, tmp_path, three):
        """All three secret outcomes at once, which is what separates the keys.

        One repo lists its secrets, one's listing is refused, and one holds none. The
        third is what makes `caveats` non-empty from a *rotation* note rather than an
        org-level one — without it, asserting equality against `report.caveats` was
        comparing two empty lists and could not see a renderer that drops the
        rotation-derived half.
        """
        named = make_multi_repo(tmp_path, "r2")
        unlistable = make_multi_repo(tmp_path, "web")
        empty = make_multi_repo(tmp_path, "docs")

        def secrets(path: Path, name: str) -> tuple[str, ...]:
            if name == "web":
                raise RuntimeError("403: admin scope required")
            return () if name == "docs" else ("AWS_KEY",)

        return scan_organization([("r2", named), ("web", unlistable), ("docs", empty)],
                                 three, runs=no_runs, secrets=secrets)

    def test_html_shows_the_unlistable_repo_beside_the_named_credential(self, mixed):
        from deptrail.report import render_html

        html = render_html(mixed)
        rotate = html.split("<h2>Rotate</h2>")[1].split("<h2>")[0]
        assert "could not be named" in rotate
        assert "web" in rotate
        # The banner is the first thing a reader sees, so it must not present the
        # credentials that could be named as the whole job.
        banner = html.split("class='banner'")[1].split("</p>")[0]
        assert "1 credential(s) to rotate" in banner
        assert "1 repository to rotate broadly" in banner

    def test_html_caveats_do_not_repeat_the_rotate_section(self, mixed):
        from deptrail.report import render_html

        html = render_html(mixed)
        for line in mixed.unnamed_rotations:
            assert html.count(escape(line)) == 1, line

    def test_json_caveats_are_exactly_the_reports_caveats(self, mixed):
        from deptrail.cli import _as_dict

        payload = _as_dict(mixed, None)
        # Equality in both directions: a superset double-counts every gap, a subset
        # silently drops the caveats that came from the rotation scan.
        assert payload["caveats"] == list(mixed.caveats)
        assert set(payload["caveats"]).isdisjoint(payload["rotate_unnamed"])
        assert set(payload["caveats"]).isdisjoint(payload["not_judged"])
        assert set(payload["caveats"]).isdisjoint(payload["incomplete_view"])
        assert payload["rotate_unnamed"], "the fixture must have an unnamed rotation"
        # Non-vacuous in the other direction too: at least one caveat must come from
        # the rotation scan, or the equality above holds for two empty lists.
        assert any("holds no secrets" in c for c in payload["caveats"]), payload["caveats"]

    def test_a_credential_keeps_every_distinct_reason_it_was_implicated_by(self):
        from deptrail.grading import Grade as G
        from deptrail.org import OrgReport
        from deptrail.rotation import Caveat, RepoRotation, RotationItem

        # Two *different* sentences about one secret. The three-package fixture merges
        # to a single cause holding three subjects, so it cannot see a renderer that
        # keeps only the first cause — and dropping the rest is the truncation this
        # change exists to remove.
        from_ci = RotationItem(repo="api", secret="K", scope=Scope.WORKFLOW, grade=G.CONFIRMED,
                               causes=(Caveat("named in ci.yml at deadbeef", ("chalk@5.6.1",)),),
                               run_ids=("1",))
        from_local = RotationItem(repo="api", secret="K", scope=Scope.DEVELOPER, grade=G.POSSIBLE,
                                  causes=(Caveat("pinned with no implicated run — "
                                                 "investigate that machine", ("debug@4.4.2",)),))
        report = OrgReport(advisory_id="x", advisory_name="x",
                           rotations=[RepoRotation(repo="api", items=[from_ci, from_local])])
        merged, = report.rotation_items
        assert len(merged.causes) == 2
        assert "named in ci.yml" in merged.reason
        assert "investigate that machine" in merged.reason
        assert "chalk@5.6.1" in merged.reason and "debug@4.4.2" in merged.reason
        # And both reach the report. Compared word by word, because the renderer folds
        # the cell across lines and the raw string is not a substring of the output.
        rendered = " ".join(render_report(report).split())
        assert " ".join(merged.reason.split()) in rendered


class TestFoldingHoldsItsPromise:
    """Folding is a promise about the output's width and about what survives in it.

    Both halves need pinning to a literal. The width assertion used to import
    `BODY_WIDTH` from the module it was testing, so widening the constant to 100000
    left the test green with the 3.3 kB line restored.
    """

    WIDTH = 96  # deliberately duplicated: a test that reads the constant tests nothing

    def _report(self, repo: str, secret: str, text: str, subjects: tuple[str, ...]):
        from deptrail.grading import Grade as G
        from deptrail.org import OrgReport
        from deptrail.rotation import Caveat, RepoRotation, RotationItem

        item = RotationItem(repo=repo, secret=secret, scope=Scope.REPO_WIDE, grade=G.CONFIRMED,
                            causes=(Caveat(text, subjects),), run_ids=("18234567890",))
        return OrgReport(advisory_id="x", advisory_name="x",
                         rotations=[RepoRotation(repo=repo, items=[item])])

    def test_the_constant_matches_the_documented_width(self):
        from deptrail.org import BODY_WIDTH

        assert BODY_WIDTH == self.WIDTH, "docs/rotation.md states 96 columns"

    def test_body_text_is_folded_even_under_a_long_identity(self):
        report = self._report(
            "platform-payments-service", "AWS_SECRET_ACCESS_KEY_PRODUCTION",
            "deploy.yml passes `secrets: inherit`", ("chalk@5.6.1", "debug@4.4.2"))
        lines = render_report(report).splitlines()
        # The identity line may be as long as the names in it; every line carrying
        # folded body text must hold the width. Ordinary repo and secret names used
        # to push the first line to 149 columns.
        body = [line for line in lines if line.startswith(" " * 16)]
        assert body, "the reason must have been folded onto a continuation line"
        assert max(len(line) for line in body) <= self.WIDTH
        assert "AWS_SECRET_ACCESS_KEY_PRODUCTION" in render_report(report)
        # And the identity keeps the line to itself. Asserting only on the folded
        # continuation lines could not see the body's first word riding along on an
        # over-long first line, which is what textwrap does with a full indent.
        identity, = [line for line in lines if "AWS_SECRET_ACCESS_KEY_PRODUCTION" in line]
        assert identity.rstrip().endswith("—"), identity
        assert "deploy.yml" not in identity

    def test_a_long_token_is_never_split(self):
        path = "services/frontend/packages/design-system/components/vendor/package-lock.json"
        report = self._report("api", "K", f"pinned in {path}, and no CI run was implicated",
                              ("chalk@5.6.1",))
        text = render_report(report)
        # The doc promises a responder can grep the saved output. Breaking a long
        # word would fold the width down at the cost of the thing being looked for.
        assert path in text
        assert "package-lock.json" in text

    def test_the_width_holds_only_up_to_the_foldable_token_length(self):
        from deptrail.org import _folded

        indent = " " * 16
        # The continuation indent counts against the width, so the real limit is not
        # BODY_WIDTH — it is BODY_WIDTH minus the indent. The 76-character fixture
        # above sits under it and so cannot see the boundary at all.
        #
        # And the unit is the whitespace-delimited chunk, not the path: a trailing
        # comma travels with it and costs one character. Writing this test against the
        # path length alone got the boundary wrong by exactly that comma.
        limit = self.WIDTH - len(indent)
        for length, expected in ((limit, True), (limit + 1, False)):
            chunk = "services/" + "a" * (length - 27) + "/package-lock.json"
            assert len(chunk) == length
            lines = _folded("  [X] api: K — ", f"pinned in {chunk} and nothing ran", indent)
            assert any(chunk in line for line in lines), "the chunk must survive whole"
            assert (max(len(line) for line in lines) <= self.WIDTH) is expected, chunk

    def test_a_path_with_a_space_is_the_case_folding_cannot_keep(self):
        from deptrail.org import _folded

        # Whitespace is legal in a git path, and it is what makes a path not one
        # token. Documented as the exception rather than claimed away, so this pins
        # the honest behaviour: the words survive, the exact path string does not.
        spaced = "services/" + "a" * 38 + " " + "b" * 32 + "/package-lock.json"
        lines = _folded("  [CONFIRMED  ] api: K [REPO_WIDE] — ",
                        f"pinned in {spaced}, and nothing ran", " " * 16)
        assert not any(spaced in line for line in lines)
        assert any("package-lock.json" in line for line in lines)

    def test_nothing_to_say_produces_no_line_at_all(self):
        from deptrail.org import _folded

        # Not reachable from a scan today — every caveat is repo-prefixed, so its body
        # is never empty. Guarded anyway because the failure is silent in a specific
        # way: a blank line lands *inside* a section, and this project reads its own
        # terminal output as blank-line-delimited sections.
        assert _folded("  ", "", " " * 4) == []
        assert _folded("  api: ", "", " " * 4) == ["  api:"]

    def test_every_subject_survives_at_advisory_scale(self):
        subjects = tuple(f"pkg-{i:03d}@{i}.0.1" for i in range(180))
        report = self._report("api", "K", "pinned in package-lock.json, and no CI run "
                              "was implicated", subjects)
        text = render_report(report)
        body = [line for line in text.splitlines() if line.startswith(" " * 16)]
        assert max(len(line) for line in body) <= self.WIDTH
        for subject in subjects:
            assert subject in text, subject


class TestRenderedShapeIsPinned:
    def test_subjects_are_listed_in_first_appearance_order(self):
        from deptrail.rotation import Caveat, merge_caveats

        # Ordered so that sorting would change it: a fixture already in sorted order
        # cannot tell first-appearance from `sorted()`.
        merged, = merge_caveats([Caveat("one sentence", ("zeta@9.0.0",)),
                                 Caveat("one sentence", ("alpha@1.0.0",)),
                                 Caveat("one sentence", ("mu@5.0.0",))])
        assert merged.subjects == ("zeta@9.0.0", "alpha@1.0.0", "mu@5.0.0")
        assert merged.rendered.endswith("(covers zeta@9.0.0, alpha@1.0.0, mu@5.0.0)")

    def test_the_sentence_comes_before_the_subjects(self):
        from deptrail.rotation import Caveat

        rendered = Caveat("what is true", ("a@1", "b@2")).rendered
        # README states each line ends with the versions it covers, and the ordering
        # is the whole reason the sentence is not buried at 180 subjects.
        assert rendered.startswith("what is true")
        assert rendered == "what is true (covers a@1, b@2)"


class TestRotationItemRefusesToBeReasonless:
    def test_an_empty_cause_tuple_is_refused(self):
        from deptrail.grading import Grade as G
        from deptrail.rotation import Caveat, RotationItem

        # Dropping the field's default stops it being forgotten; it does not stop an
        # explicit `()`, and either renders a credential on a checklist with its
        # reason missing — a rotation line ending in a bare em dash.
        with pytest.raises(ValueError, match="no cause"):
            RotationItem(repo="api", secret="K", scope=Scope.REPO_WIDE, grade=G.CONFIRMED,
                         causes=())
        valid = RotationItem(repo="api", secret="K", scope=Scope.REPO_WIDE,
                             grade=G.CONFIRMED, causes=(Caveat("because"),))
        with pytest.raises(ValueError, match="no cause"):
            replace(valid, causes=())


class TestRenderersDeriveTheMergeOnce:
    """``rotation_items`` is quadratic in the items, so each renderer gets one look.

    This is a performance contract with a correctness-shaped consequence: the report a
    responder reads during an incident took 44 s to produce when one renderer derived
    it three times, and 27 s when the JSON path did. Both were found by review rather
    than by a test, twice, which is what this pins.
    """

    @staticmethod
    def _counting_report():
        from deptrail.grading import Grade as G
        from deptrail.org import OrgReport
        from deptrail.rotation import Caveat, RepoRotation, RotationItem

        item = RotationItem(repo="api", secret="K", scope=Scope.DEVELOPER, grade=G.POSSIBLE,
                            causes=(Caveat("pinned in package-lock.json", ("chalk@5.6.1",)),))
        return OrgReport(advisory_id="x", advisory_name="x",
                         rotations=[RepoRotation(repo="api", items=[item])])

    @pytest.mark.parametrize("renderer", ["text", "html", "json"])
    def test_one_derivation_per_render(self, renderer, monkeypatch):
        from deptrail.cli import _as_dict
        from deptrail.org import OrgReport
        from deptrail.report import render_html

        calls = []
        original = OrgReport.rotation_items.fget
        monkeypatch.setattr(
            OrgReport, "rotation_items",
            property(lambda self: (calls.append(1), original(self))[1]),
        )
        report = self._counting_report()
        {"text": lambda: render_report(report),
         "html": lambda: render_html(report),
         "json": lambda: _as_dict(report, None)}[renderer]()
        assert len(calls) == 1, f"{renderer} derived the rotation merge {len(calls)} times"


class TestAbsenceIsNeverProvenAlongsideAnExposure:
    def test_an_exposed_repo_stops_the_all_clear(self, tmp_path, plan):
        repo = make_repo(tmp_path, "api", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        report = scan_organization([("api", repo)], plan, runs=no_runs,
                                   secrets=lambda p, n: ())
        # The repository holds no secrets, so there is no rotation item to raise the exit
        # code and no unread tree to lower it — and the exposure is in the timeline.
        # `proves_absence` is the sentence exit 0 speaks; it cannot be true here.
        assert report.exposed_repos == ("api",)
        assert report.rotation_items == ()
        assert report.proves_absence is False

    def test_a_clean_repo_still_proves_absence(self, tmp_path, plan):
        repo = make_repo(tmp_path, "web", [("2025-11-25T10:00:00+00:00", "5.6.0")])
        report = scan_organization([("web", repo)], plan, runs=no_runs,
                                   secrets=secrets_provider)
        assert report.exposed_repos == ()
        assert report.proves_absence is True

    def test_a_set_aside_fixture_still_proves_absence(self, tmp_path, plan):
        # A fixture tree raises no credential and is not an exposure of the repository,
        # so it must not cost every tooling project its all-clear either.
        repo = tmp_path / "tool"
        (repo / "tests/fixtures").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / "tests/fixtures/package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "fixtures", date="2025-11-25T10:00:00+00:00")
        report = scan_organization([("tool", repo)], plan, runs=no_runs,
                                   secrets=secrets_provider)
        assert report.exposed_repos == ()
        assert report.set_aside
        assert report.proves_absence is True


class TestWorkflowsAreReadAtTheCommit:
    """Superseded the heuristic install-detection cases; what remains is which *commit's*
    workflows are consulted, and which set of them wins."""

    def test_the_workflows_are_read_at_the_commit_not_at_head(self, tmp_path, plan):
        # A workflow that installed the directory during the window and was retired
        # afterwards is exactly the evidence that matters. Reading HEAD instead loses it,
        # and the repository is cleared — a false clean, with no CI records needed.
        repo = tmp_path / "retired"
        (repo / "examples/app").mkdir(parents=True)
        (repo / ".github/workflows").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / ".github/workflows/deploy.yml").write_text(
            "name: Deploy\non: [push]\njobs:\n  d:\n    steps:\n"
            "      - run: npm ci --prefix examples/app\n")
        (repo / "examples/app/package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        (repo / ".github/workflows/deploy.yml").unlink()
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "retire the deploy workflow",
            date="2026-01-10T10:00:00+00:00")
        report = scan_organization([("retired", repo)], plan, runs=no_runs,
                                   secrets=lambda p, n: ("NPM_TOKEN",))
        # The literal install is actionable even after its run record expires. Reading
        # HEAD instead would find no workflow and file the application as fixture data.
        assert report.exposed_repos == ("retired",)
        assert {item.secret for item in report.rotation_items} == {"NPM_TOKEN"}
        assert report.proves_absence is False

    def test_the_implicated_workflows_are_consulted_before_every_workflow(self, tmp_path,
                                                                         plan):
        # The fallback is a fallback. CI ran only ci.yml, which installs at the root and
        # says nothing about examples/app; an unrelated workflow at the same commit does
        # install there but never ran. Preferring the second over the first would report
        # an exposure on a tree the implicated run did not touch.
        repo = tmp_path / "twoflows"
        (repo / "examples/app").mkdir(parents=True)
        (repo / ".github/workflows").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / ".github/workflows/ci.yml").write_text(
            "name: CI\non: [push]\njobs:\n  b:\n    steps:\n      - run: npm ci\n")
        (repo / ".github/workflows/examples.yml").write_text(
            "name: Examples\non: [workflow_dispatch]\njobs:\n  e:\n    steps:\n"
            "      - run: npm ci --prefix examples/app\n")
        (repo / "examples/app/package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        report = scan_organization([("twoflows", repo)], plan,
                                   runs=runs_with(head(repo)),
                                   secrets=lambda p, n: ("NPM_TOKEN",))
        # The implicated workflow does not name it, so the CONFIRMED path does not fire and
        # the tree is not treated as installed. It is still named by another workflow at
        # that commit, so it is not cleared either.
        assert report.exposed_repos == ()
        assert report.unresolved


class TestMentionsComparesPaths:
    """Path segments, not substrings and not a boundary regex — both were wrong on real
    input. `"test"` matched `ubuntu-latest`; a regex boundary still matched
    `vendor/examples/app` and `examples/app.bak` when the tree was `examples/app`."""

    CASES = [
        ("examples/app", True), ("./examples/app", True), ('"examples/app"', True),
        ("'examples/app'", True), ("examples/app/", True),
        ("examples/app/package-lock.json", True),
        (r".\examples\app", True),
        ("$GITHUB_WORKSPACE/examples/app", True),
        ("${{ github.workspace }}/examples/app", True),
        ("cd examples/app && npm ci", True),
        ("my-examples/app", False), ("vendor/examples/app", False),
        ("../examples/app", False),
        ("examples/app.bak", False), ("examples/application", False),
        ("examples", False), ("app", False),
    ]

    @pytest.mark.parametrize("text,expected", CASES)
    def test_examples_app(self, text, expected):
        from deptrail.org import _mentions

        assert _mentions(text, "examples/app") is expected, text

    def test_a_word_containing_the_name_is_not_the_directory(self):
        from deptrail.org import _mentions

        # The case that started this: a `test/` lockfile matched almost every workflow
        # ever written, because `runs-on: ubuntu-latest` contains the letters.
        assert _mentions("runs-on: ubuntu-latest", "test") is False
        assert _mentions("run: python -m pytest", "test") is False
        assert _mentions("run: npm ci --prefix test", "test") is True

    def test_a_quoted_path_may_contain_whitespace(self):
        from deptrail.org import _mentions

        assert _mentions("working-directory: 'examples/my app'", "examples/my app")


class TestClassifyingATreeHasThreeAnswers:
    """Only a literal executable install is YES without a run; opaque work is UNKNOWN.

    Deciding the second by pattern-matching YAML was wrong four times, in both directions
    at once by the fourth attempt: an install arrives through a composite action, a wrapper
    script, a matrix variable, `npm i`, a bare `yarn` or a reusable workflow in another
    repository, and a directory name appears in step titles, runner labels and echoed
    strings. The narrower question is answerable, and the third answer carries the
    uncertainty instead of a heuristic pretending to resolve it.
    """

    from deptrail.org import Installed

    DIRECT_INSTALLS = {
        "a prefixed install": "      - run: npm ci --prefix examples/app\n",
        "flags before the verb": "      - run: npm --workspace examples/app install\n",
        "a Windows path": r"      - run: npm ci --prefix .\examples\app" + "\n",
        "flow-style steps": "      steps: [{run: npm ci --prefix examples/app}]\n",
    }
    NAMED = {
        "a scoped step": "      - working-directory: examples/app\n        run: npm ci\n",
        "a bare package manager": "      - run: |\n          cd examples/app\n          yarn\n",
        "a step title": "      - name: build examples/app\n        run: make\n",
        "a comment": "      # deploys examples/app\n      - run: npm ci\n",
        "a test command": "      - working-directory: examples/app\n        run: npm test\n",
        "an echoed command": "      - run: echo 'npm ci --prefix examples/app'\n",
    }
    NOT_NAMED = {
        "a runner label only": "      - runs-on: ubuntu-latest\n        run: npm ci\n",
        "a longer sibling path":
            "      - working-directory: examples/application\n        run: npm ci\n",
        "a path that contains it":
            "      - run: npm ci --prefix vendor/examples/app\n",
        "a backup of it": "      - run: cp -r examples/app.bak .\n",
        "an install at the root": "      - run: npm ci\n",
    }
    AMBIGUOUS = {
        "a local action": "      - uses: ./.github/actions/setup\n",
        "a wrapper script": "      - run: ./scripts/install-all\n",
        "a tool wrapper": "      - run: ./tools/build\n",
        "a shell wrapper": "      - run: bash scripts/setup.sh\n",
        "a remote reusable workflow":
            "      uses: owner/repo/.github/workflows/build.yml@main\n",
        "a dynamic directory":
            "      - working-directory: ${{ matrix.dir }}\n        run: npm ci\n",
        "workspace install without a readable member": "      - run: npm ci --workspaces\n",
    }

    def _classify(self, tmp_path, name, steps, runs=None, *, directory="examples/app",
                  workspace=False):
        from deptrail.grading import grade_finding
        from deptrail.history import scan_repo
        from deptrail.org import _classify_tree

        repo = tmp_path / name
        (repo / directory).mkdir(parents=True)
        (repo / ".github/workflows").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / ".github/workflows/ci.yml").write_text(
            "name: CI\non: [push]\njobs:\n  b:\n    steps:\n" + steps)
        if workspace:
            (repo / "package.json").write_text(json.dumps({
                "name": "root", "private": True, "workspaces": ["examples/*"],
            }))
        (repo / directory / "package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        query = self.plan.entries[0].query
        walked = scan_repo(repo, query)
        provider = runs(repo) if runs else no_runs
        graded = grade_finding(walked, query, provider(repo, name))
        assert graded.graded, "the fixture must produce an exposure"
        return _classify_tree(repo, graded.graded[0]), repo

    @pytest.fixture(autouse=True)
    def _plan(self, plan):
        self.plan = plan

    @pytest.mark.parametrize("label", list(DIRECT_INSTALLS))
    def test_a_literal_install_is_yes_without_a_retained_run(self, tmp_path, label):
        # POSSIBLE is already an actionable grade. Losing the run record may widen the
        # credential scope, but it must not delete a literal install from the checklist.
        answer, _ = self._classify(tmp_path, f"d{abs(hash(label)) % 9999}",
                                   self.DIRECT_INSTALLS[label])
        assert answer is self.Installed.YES, label

    @pytest.mark.parametrize("label", list(NAMED))
    def test_named_without_a_run_is_unknown(self, tmp_path, label):
        # Named, with no run implicated to say it executed. Under stronger CI evidence this
        # would have been kept, so calling it test data makes the classification a function
        # of what the runs API happened to return.
        answer, _ = self._classify(tmp_path, f"u{abs(hash(label)) % 9999}",
                                   self.NAMED[label])
        assert answer is self.Installed.UNKNOWN, label

    @pytest.mark.parametrize("label", list(AMBIGUOUS))
    def test_delegated_or_dynamic_install_is_unknown(self, tmp_path, label):
        answer, _ = self._classify(tmp_path, f"a{abs(hash(label)) % 9999}",
                                   self.AMBIGUOUS[label])
        assert answer is self.Installed.UNKNOWN, label

    @pytest.mark.parametrize("label", list(NOT_NAMED))
    def test_not_named_is_no(self, tmp_path, label):
        answer, _ = self._classify(tmp_path, f"n{abs(hash(label)) % 9999}",
                                   self.NOT_NAMED[label])
        assert answer is self.Installed.NO, label

    def test_named_with_a_confirmed_run_is_yes(self, tmp_path):
        steps = ("      - run: npm ci --prefix examples/app\n"
                 "      - run: deploy\n        env:\n"
                 "          T: ${{ secrets.NPM_TOKEN }}\n")
        answer, _ = self._classify(
            tmp_path, "confirmed", steps,
            runs=lambda repo: runs_with(head(repo)))
        assert answer is self.Installed.YES

    def test_a_root_workspace_install_is_actionable(self, tmp_path):
        answer, _ = self._classify(
            tmp_path, "workspace", "      - run: npm ci --workspaces\n", workspace=True)
        assert answer is self.Installed.YES

    def test_a_literal_install_path_may_contain_whitespace(self, tmp_path):
        answer, _ = self._classify(
            tmp_path, "spaces", "      - run: npm ci --prefix 'examples/my app'\n",
            directory="examples/my app")
        assert answer is self.Installed.YES

    def test_a_root_lockfile_needs_no_workflow_at_all(self, tmp_path, plan):
        repo = make_repo(tmp_path, "root", [("2025-11-25T10:00:00+00:00", "5.6.1")])
        report = scan_organization([("root", repo)], plan, runs=no_runs,
                                   secrets=lambda p, n: ("NPM_TOKEN",))
        assert report.exposed_repos == ("root",)


class TestUnknownIsNeitherActedOnNorCleared:
    def _report(self, tmp_path, plan, name="delegated"):
        repo = tmp_path / name
        (repo / "examples/app").mkdir(parents=True)
        (repo / ".github/workflows").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / ".github/workflows/ci.yml").write_text(
            "name: CI\non: [push]\njobs:\n  b:\n    steps:\n"
            "      - run: ./scripts/install-all\n")
        (repo / "examples/app/package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        return scan_organization([(name, repo)], plan, runs=no_runs,
                                 secrets=lambda p, n: ("NPM_TOKEN",))

    def test_it_raises_no_credential_and_stops_the_all_clear(self, tmp_path, plan):
        from deptrail.cli import EXIT_INCOMPLETE, _exit_code

        report = self._report(tmp_path, plan)
        assert report.rotation_items == ()
        assert report.exposed_repos == ()
        assert report.unresolved
        assert report.proves_absence is False
        assert _exit_code(report) == EXIT_INCOMPLETE

    def test_it_is_not_also_reported_as_not_installed(self, tmp_path, plan):
        report = self._report(tmp_path, plan)
        # One exposure, one statement about it. Both flags came off the same boolean, so it
        # appeared under "not installed by any workflow" and "could not classify" at once.
        assert report.set_aside == ()
        assert len(report.unclassified) == 1
        text = render_report(report)
        assert "set aside" not in text
        assert "could not classify" in text

    def test_it_counts_toward_the_worst_grade(self, tmp_path, plan):
        report = self._report(tmp_path, plan)
        # A report that names a compromised version it declined to clear cannot also say
        # its worst grade is NO_EVIDENCE.
        assert report.worst_grade is Grade.POSSIBLE

    def test_it_reaches_all_three_renderers(self, tmp_path, plan):
        from deptrail.cli import _as_dict
        from deptrail.report import render_html

        report = self._report(tmp_path, plan, name="delegated2")
        assert "could not classify" in render_report(report)
        assert "Could not classify" in render_html(report)
        payload = _as_dict(report, None)
        assert payload["unclassified"] == list(report.unresolved)
        assert payload["set_aside"] == []


class TestWorkflowReadFailureIsNotNoWorkflow:
    def test_an_unreadable_listed_blob_cannot_clear_the_tree(self, tmp_path, plan,
                                                             monkeypatch):
        from deptrail.cli import EXIT_INCOMPLETE, _exit_code

        repo = tmp_path / "unread-workflow"
        (repo / "examples/app").mkdir(parents=True)
        (repo / ".github/workflows").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / ".github/workflows/ci.yml").write_text(
            "name: CI\non: [push]\njobs:\n  b:\n    steps:\n"
            "      - run: npm ci --prefix examples/app\n")
        (repo / "examples/app/package-lock.json").write_text(lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "deps", date="2025-11-25T10:00:00+00:00")
        monkeypatch.setattr("deptrail.org._text_at", lambda *args: None)

        report = scan_organization([("unread-workflow", repo)], plan, runs=no_runs,
                                   secrets=lambda p, n: ("NPM_TOKEN",))

        assert report.set_aside == ()
        assert report.unresolved
        assert report.proves_absence is False
        assert _exit_code(report) == EXIT_INCOMPLETE
