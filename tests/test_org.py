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
        assert any("locally" in i.reason for i in items)

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
        assert report.exposed_repos == ("api",)
        assert not report.proves_absence

    def test_partial_advisory_never_proves_absence(self, tmp_path):
        partial = dict(ADVISORY, coverage="partial")
        plan = parse_advisory(json.dumps(partial)).plan()
        clean = make_repo(tmp_path, "web", [("2025-11-25T10:00:00+00:00", "5.6.0")])
        report = scan_organization([("web", clean)], plan, runs=no_runs)
        assert report.worst_grade is Grade.NO_EVIDENCE
        assert not report.proves_absence
        assert any("partial coverage" in n for n in report.notes)

    def test_unreadable_history_reaches_the_rotation_list(self, tmp_path, plan):
        origin = make_repo(tmp_path, "origin", [
            ("2025-11-25T10:00:00+00:00", "5.6.1"),
            ("2025-11-28T10:00:00+00:00", "5.6.2"),
        ])
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}",
                        str(shallow)], check=True, capture_output=True)
        report = scan_organization([("shallow", shallow)], plan, runs=no_runs,
                                  secrets=secrets_provider)
        assert report.rotation_items, "a repo we could not read must not be cleared"
        assert {i.scope for i in report.rotation_items} == {Scope.REPO_WIDE}


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
