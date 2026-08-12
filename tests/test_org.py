"""Tests for the organization scan and the rotation list it produces.

The rotation list is the deliverable, so these tests assert what a responder
would act on: which credentials appear, why, and when the report refuses to
claim an all-clear.
"""
import json
import os
import subprocess
from datetime import datetime, timezone
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
