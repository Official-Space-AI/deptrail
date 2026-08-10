"""Integration tests for the history walker against synthetic git repos.

Each test builds a real git repo with faked commit dates. The regression
classes at the bottom encode the failure scenarios found by adversarial
review of PR #8 — every one of them produced a wrong verdict before the fix.
"""
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from deptrail.history import (
    Verdict,
    WindowQuery,
    _parse_iso,
    lockfile_paths,
    scan_repo,
)

WINDOW = WindowQuery(
    package="chalk",
    malicious_versions=frozenset({"5.6.1"}),
    window_start=datetime.fromisoformat("2025-11-24T00:00:00+00:00"),
    window_end=datetime.fromisoformat("2025-11-26T23:59:59+00:00"),
)


def git(repo: Path, *args: str, date: str | None = None, author_date: str | None = None) -> None:
    env = dict(os.environ)
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    if author_date:
        env["GIT_AUTHOR_DATE"] = author_date
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True, capture_output=True, env=env,
    )


def lock_json(chalk_version: str | None) -> str:
    packages = {
        "": {"dependencies": {"express": "^4.19.0"}},
        "node_modules/express": {"version": "4.19.2", "dependencies": {"debug": "^4.3.4"}},
        "node_modules/debug": {"version": "4.3.5", "dependencies": {"chalk": "^5.6.0"}},
    }
    if chalk_version:
        packages["node_modules/chalk"] = {"version": chalk_version}
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages})


def make_repo(tmp_path: Path, name: str, states: list[tuple[str, str | None]],
              lockfile: str = "package-lock.json") -> Path:
    """states: list of (ISO commit date, chalk version or None to drop chalk)."""
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    for i, (date, version) in enumerate(states):
        target = repo / lockfile
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(lock_json(version))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"chore: state {i}", date=date)
    return repo


class TestExposureJudgment:
    def test_exposed_interval_overlapping_window(self, tmp_path):
        repo = make_repo(tmp_path, "exposed", [
            ("2025-11-20T10:00:00+00:00", "5.6.0"),
            ("2025-11-25T14:30:00+00:00", "5.6.1"),
            ("2025-11-28T09:00:00+00:00", "5.6.2"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        exp = finding.exposures[0]
        assert exp.version == "5.6.1"
        assert exp.chain == ("express", "debug", "chalk")
        assert exp.evidence == "interval:HEAD"
        assert not exp.still_pinned

    def test_clean_when_version_skipped_over_window(self, tmp_path):
        repo = make_repo(tmp_path, "clean", [
            ("2025-11-10T11:00:00+00:00", "5.6.0"),
            ("2025-11-29T16:00:00+00:00", "5.6.2"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.CLEAN and not finding.warnings

    def test_exposure_before_window_does_not_count(self, tmp_path):
        repo = make_repo(tmp_path, "early", [
            ("2025-11-01T10:00:00+00:00", "5.6.1"),
            ("2025-11-20T10:00:00+00:00", "5.6.2"),
        ])
        assert scan_repo(repo, WINDOW).verdict is Verdict.CLEAN

    def test_still_pinned_is_open_interval(self, tmp_path):
        repo = make_repo(tmp_path, "pinned", [
            ("2025-11-25T14:30:00+00:00", "5.6.1"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed and finding.exposures[0].still_pinned

    def test_no_lockfile_repo(self, tmp_path):
        repo = tmp_path / "none"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "README.md").write_text("hi")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init", date="2025-11-01T00:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.CLEAN and finding.lockfiles_seen == 0

    def test_interval_touching_window_start_is_not_exposure(self, tmp_path):
        # Held interval [11-20, 11-24T00:00) and window starting exactly 11-24T00:00
        # share no instant: half-open until must not count equality as overlap.
        repo = make_repo(tmp_path, "boundary", [
            ("2025-11-20T10:00:00+00:00", "5.6.1"),
            ("2025-11-24T00:00:00+00:00", "5.6.2"),
        ])
        assert scan_repo(repo, WINDOW).verdict is Verdict.CLEAN


class TestMonorepoAndWarnings:
    def test_monorepo_judges_each_lockfile(self, tmp_path):
        repo = tmp_path / "mono"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "packages/api").mkdir(parents=True)
        (repo / "packages/web").mkdir(parents=True)
        (repo / "packages/api/package-lock.json").write_text(lock_json("5.6.1"))
        (repo / "packages/web/package-lock.json").write_text(lock_json("5.6.0"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.lockfiles_seen == 2
        assert {e.lockfile_path for e in finding.exposures} == {"packages/api/package-lock.json"}

    def test_deleted_lockfile_history_still_examined(self, tmp_path):
        repo = make_repo(tmp_path, "deleted", [
            ("2025-11-25T12:00:00+00:00", "5.6.1"),
        ])
        (repo / "package-lock.json").unlink()
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "chore: drop lockfile", date="2025-11-26T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert not finding.exposures[0].still_pinned

    def test_unreadable_snapshot_warns_and_verdict_is_indeterminate(self, tmp_path):
        repo = tmp_path / "broken"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package-lock.json").write_text("{ not json at all")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "bad", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.warnings and "unreadable" in finding.warnings[0]
        assert finding.verdict is Verdict.INDETERMINATE


class TestReviewRegressions:
    """Each test reproduces a confirmed wrong-verdict scenario from the PR #8 review."""

    def test_clock_skew_does_not_hide_exposure(self, tmp_path):
        # Parent's clock runs 2 days ahead: dates are non-monotonic in graph order.
        # Date-sorting produced [11-20, 11-22) for the malicious pin -> false clean.
        repo = make_repo(tmp_path, "skew", [
            ("2025-11-22T10:00:00+00:00", "5.6.0"),  # parent, clock ahead
            ("2025-11-20T10:00:00+00:00", "5.6.1"),  # child, true pin
            ("2025-11-27T10:00:00+00:00", "5.6.2"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert any("predates its parent" in d for d in finding.diagnostics)

    def test_rebase_rewritten_committer_dates_still_detected(self, tmp_path):
        # Rebase rewrites committer dates to merge day; author dates keep the truth.
        repo = tmp_path / "rebased"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package-lock.json").write_text(lock_json("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "pin", date="2025-12-15T09:00:00+00:00",
            author_date="2025-11-25T14:30:00+00:00")
        (repo / "package-lock.json").write_text(lock_json("5.6.2"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "fix", date="2025-12-15T09:00:01+00:00",
            author_date="2025-11-26T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert any("diverge" in d for d in finding.diagnostics)

    def test_branch_only_exposure_is_found(self, tmp_path):
        # Malicious pin lives only on an unmerged branch; CI still built it there.
        repo = make_repo(tmp_path, "branchy", [
            ("2025-11-20T10:00:00+00:00", "5.6.0"),
        ])
        git(repo, "checkout", "-q", "-b", "feat")
        (repo / "package-lock.json").write_text(lock_json("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "pin", date="2025-11-25T12:00:00+00:00")
        git(repo, "checkout", "-q", "-")
        (repo / "package-lock.json").write_text(lock_json("5.6.2"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "bump", date="2025-12-01T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.exposures[0].evidence == "interval:refs/heads/feat"
        # The branch tip still pins it, which a remediation list must show.
        assert finding.exposures[0].still_pinned

    def test_lookalike_filenames_are_not_lockfiles(self, tmp_path):
        repo = tmp_path / "lookalike"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "fixtures").mkdir()
        (repo / "fixtures/sample-package-lock.json").write_text(lock_json("5.6.1"))
        (repo / "not-package-lock.json").write_text(lock_json("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "fixtures", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.lockfiles_seen == 0
        assert finding.verdict is Verdict.CLEAN

    def test_non_ascii_lockfile_path_is_scanned(self, tmp_path):
        repo = tmp_path / "unicode"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "café").mkdir()
        (repo / "café/package-lock.json").write_text(lock_json("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "svc", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert lockfile_paths(repo) == ["café/package-lock.json"]
        assert finding.verdict is Verdict.EXPOSED

    def test_shallow_clone_is_never_silently_clean(self, tmp_path):
        origin = make_repo(tmp_path, "origin", [
            ("2025-11-25T12:00:00+00:00", "5.6.1"),
            ("2025-11-27T12:00:00+00:00", "5.6.2"),
        ])
        shallow = tmp_path / "shallow"
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", f"file://{origin}", str(shallow)],
            check=True, capture_output=True,
        )
        finding = scan_repo(shallow, WINDOW)
        assert finding.verdict is not Verdict.CLEAN
        assert any("shallow" in w for w in finding.warnings)

    def test_ours_merge_does_not_fake_still_pinned(self, tmp_path):
        # A -s ours merge hides the replacing commit from a plain path log; the
        # old code then reported the malicious version as pinned to this day.
        repo = make_repo(tmp_path, "ours", [
            ("2025-11-10T10:00:00+00:00", "5.6.0"),
        ])
        default = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        git(repo, "checkout", "-q", "-b", "fix")
        (repo / "package-lock.json").write_text(lock_json("5.6.2"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "safe", date="2025-11-12T10:00:00+00:00")
        git(repo, "checkout", "-q", "-")
        (repo / "package-lock.json").write_text(lock_json("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "pin", date="2025-11-20T10:00:00+00:00")
        git(repo, "checkout", "-q", "fix")
        git(repo, "merge", "-q", "-s", "ours", default, "-m", "merge",
            date="2025-11-26T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        # The malicious pin on master's line is real exposure evidence. HEAD
        # holds 5.6.2, so the interval that HEAD established must be closed.
        assert finding.exposed
        assert not any(e.still_pinned for e in finding.exposures
                       if e.evidence == "interval:HEAD")

    def test_per_version_chains_differ(self, tmp_path):
        # Two malicious versions entering through different parents must carry
        # their own chains, not share one.
        both_bad = WindowQuery(
            package="chalk",
            malicious_versions=frozenset({"5.6.1", "4.1.2"}),
            window_start=WINDOW.window_start,
            window_end=WINDOW.window_end,
        )
        packages = {
            "": {"dependencies": {"express": "^4.19.0", "picolog": "^2.0.0"}},
            "node_modules/express": {"version": "4.19.2", "dependencies": {"debug": "^4.3.4"}},
            "node_modules/debug": {"version": "4.3.5", "dependencies": {"chalk": "^5.6.0"}},
            "node_modules/chalk": {"version": "5.6.1"},
            "node_modules/picolog": {"version": "2.0.0", "dependencies": {"chalk": "^4.0.0"}},
            "node_modules/picolog/node_modules/chalk": {"version": "4.1.2"},
        }
        repo = tmp_path / "chains"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package-lock.json").write_text(
            json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages})
        )
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, both_bad)
        chains = {e.version: e.chain for e in finding.exposures}
        assert chains["4.1.2"] == ("picolog", "chalk")  # physical nesting
        assert chains["5.6.1"][-1] == "chalk"

    def test_iso_z_suffix_parses_on_all_supported_pythons(self):
        assert _parse_iso("2025-11-25T00:00:00Z").tzinfo is not None


YARN_LOCK = """\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"chalk@^5.6.0":
  version "5.6.1"
  resolved "https://registry.yarnpkg.com/chalk/-/chalk-5.6.1.tgz"
"""


class TestUnreadableTrees:
    """A tree we cannot read must never be reported as a tree without exposure.

    Every case here answered CLEAN before the fix, including one that pinned the
    malicious version inside the window — see issue #16.
    """

    def test_shrinkwrap_is_a_first_class_lockfile(self, tmp_path):
        # npm-shrinkwrap.json is npm's own lockfile and uses the same schema, so
        # it is scanned rather than merely acknowledged.
        repo = make_repo(tmp_path, "shrinkwrap", [
            ("2025-11-25T12:00:00+00:00", "5.6.1"),
        ], lockfile="npm-shrinkwrap.json")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.exposures[0].lockfile_path == "npm-shrinkwrap.json"
        assert finding.unread_trees == []

    def test_yarn_lockfile_is_indeterminate_not_clean(self, tmp_path):
        repo = tmp_path / "yarn"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "yarn.lock").write_text(YARN_LOCK)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "lock", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]
        assert "Yarn" in finding.unread_trees[0].reason
        # An unread tree is not a lost warning: nothing suggests exposure either.
        assert finding.warnings == []

    def test_pnpm_lockfile_is_indeterminate_not_clean(self, tmp_path):
        repo = tmp_path / "pnpm"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "lock", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert [t.path for t in finding.unread_trees] == ["pnpm-lock.yaml"]

    def test_node_project_without_any_lockfile_is_indeterminate(self, tmp_path):
        repo = tmp_path / "unlocked"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package.json").write_text('{"name":"app","dependencies":{"chalk":"^5.6.0"}}')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "manifest", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        # The manifest's own path is kept, so a caller can judge which tree it is.
        assert [t.path for t in finding.unread_trees] == ["package.json"]

    def test_repository_that_is_not_a_node_project_is_clean(self, tmp_path):
        # The honest opposite: nothing to read because there was nothing to read.
        repo = tmp_path / "python"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "main.py").write_text("print(1)\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "code", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.CLEAN
        assert finding.unread_trees == []

    def test_npm_lockfile_alongside_a_yarn_one_is_both_judged_and_flagged(self, tmp_path):
        repo = make_repo(tmp_path, "mixed", [
            ("2025-11-25T12:00:00+00:00", "5.6.1"),
        ])
        (repo / "mobile").mkdir()
        (repo / "mobile/yarn.lock").write_text(YARN_LOCK)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "add the mobile app", date="2025-11-25T13:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED           # the npm tree was read
        assert [t.path for t in finding.unread_trees] == ["mobile/yarn.lock"]

    def test_a_manifest_is_not_reported_when_a_foreign_lockfile_already_is(self, tmp_path):
        repo = tmp_path / "yarn-with-manifest"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "yarn.lock").write_text(YARN_LOCK)
        (repo / "package.json").write_text('{"name":"app"}')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "app", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]


class TestLockCoverageIsPerTreeAndPerWindow:
    """Review of the #16 fix: judging lock coverage per *repository* was wrong in
    both directions at once. Every case here was verified against the real tool
    before and after — see docs/experiments.md E13."""

    def write(self, repo, path, body, date):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"write {path}", date=date)

    def fresh(self, tmp_path, name):
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "-q")
        return repo

    def test_lockfile_deleted_before_the_window_no_longer_clears_the_repo(self, tmp_path):
        # The tree carried a package.json and no lock while 5.6.1 was installable,
        # so what it installed then is unknown. This reported CLEAN and exit 0.
        repo = self.fresh(tmp_path, "dropped")
        self.write(repo, "package.json", '{"name":"app"}', "2025-11-01T10:00:00+00:00")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-01T11:00:00+00:00")
        (repo / "package-lock.json").unlink()
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "drop the lock", date="2025-11-10T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert [t.path for t in finding.unread_trees] == ["package.json"]

    def test_one_locked_app_does_not_clear_its_unlocked_sibling(self, tmp_path):
        repo = self.fresh(tmp_path, "monorepo")
        (repo / "locked").mkdir()
        (repo / "locked/package.json").write_text('{"name":"l"}')
        self.write(repo, "locked/package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        self.write(repo, "unlocked/package.json", '{"name":"u"}',
                   "2025-11-25T11:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["unlocked/package.json"]

    def test_a_fixture_lockfile_does_not_clear_the_root_tree(self, tmp_path):
        # The fixture lock is real but governs only tests/fixtures; the deployed
        # root tree still had nothing we could read.
        repo = self.fresh(tmp_path, "fixture-only")
        self.write(repo, "package.json", '{"name":"app"}', "2025-11-25T10:00:00+00:00")
        self.write(repo, "tests/fixtures/package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:30:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["package.json"]

    def test_a_workspace_root_lockfile_covers_its_packages(self, tmp_path):
        # The other direction: npm workspaces keep one lock at the root, so a
        # package without its own lock is governed, not unread.
        repo = self.fresh(tmp_path, "workspace")
        (repo / "package.json").write_text(
            '{"name":"root","private":true,"workspaces":["packages/*"]}')
        (repo / "packages/api").mkdir(parents=True)
        (repo / "packages/api/package.json").write_text('{"name":"api"}')
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.unread_trees == []
        assert finding.verdict is Verdict.CLEAN

    def test_foreign_lockfile_removed_before_the_window_is_not_held_against_the_repo(
            self, tmp_path):
        # A project that migrated off Yarn years ago was denied an all-clear
        # forever, because every foreign lockfile ever committed counted.
        repo = self.fresh(tmp_path, "migrated")
        self.write(repo, "yarn.lock", YARN_LOCK, "2025-11-01T10:00:00+00:00")
        (repo / "yarn.lock").unlink()
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-02T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.unread_trees == []
        assert finding.verdict is Verdict.CLEAN

    def test_foreign_lockfile_added_after_the_window_is_not_held_against_the_repo(
            self, tmp_path):
        repo = self.fresh(tmp_path, "adopted")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-01T10:00:00+00:00")
        self.write(repo, "yarn.lock", YARN_LOCK, "2025-12-20T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.unread_trees == []

    def test_foreign_lockfile_present_during_the_window_still_counts(self, tmp_path):
        repo = self.fresh(tmp_path, "yarn-live")
        self.write(repo, "yarn.lock", YARN_LOCK, "2025-11-20T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]

    def test_shrinkwrap_takes_precedence_over_package_lock(self, tmp_path):
        # npm ignores package-lock.json when a shrinkwrap sits beside it, so the
        # malicious pin in the ignored file is not an exposure.
        repo = self.fresh(tmp_path, "both")
        self.write(repo, "npm-shrinkwrap.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        self.write(repo, "package-lock.json", lock_json("5.6.1"),
                   "2025-11-25T10:30:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.exposures == []
        assert finding.verdict is Verdict.CLEAN

    def test_package_lock_still_counts_before_the_shrinkwrap_appears(self, tmp_path):
        # Precedence is decided per commit: while no shrinkwrap existed, the
        # package-lock is what npm read.
        repo = self.fresh(tmp_path, "later-shrinkwrap")
        self.write(repo, "package-lock.json", lock_json("5.6.1"),
                   "2025-11-25T10:00:00+00:00")
        self.write(repo, "npm-shrinkwrap.json", lock_json("5.6.0"),
                   "2025-11-26T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [e.version for e in finding.exposures] == ["5.6.1"]

    def test_manifest_lookalikes_are_not_manifests(self, tmp_path):
        # `*package.json` also matches metadata-package.json; one such file made a
        # Python repository exit 2.
        repo = self.fresh(tmp_path, "lookalike-manifest")
        self.write(repo, "metadata-package.json", '{"a":1}',
                   "2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.unread_trees == []
        assert finding.verdict is Verdict.CLEAN

    def test_dependency_manifests_under_node_modules_are_not_trees(self, tmp_path):
        # A committed node_modules holds one manifest per package; each is a
        # dependency's own file, not a tree anybody locks. Asserted on discovery
        # directly: with a root lockfile in place the exclusion cannot be seen from
        # the verdict, so a version of this test that only checked unread_trees
        # passed with the exclusion removed.
        from deptrail.history import manifest_paths
        repo = self.fresh(tmp_path, "vendored")
        (repo / "node_modules/chalk").mkdir(parents=True)
        (repo / "node_modules/chalk/package.json").write_text('{"name":"chalk"}')
        (repo / "packages/api").mkdir(parents=True)
        (repo / "packages/api/package.json").write_text('{"name":"api"}')
        self.write(repo, "packages/api/package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        assert manifest_paths(repo) == ["packages/api/package.json"]
        finding = scan_repo(repo, WINDOW)
        assert finding.unread_trees == []


class TestPartialCoverageAndPrecedence:
    """Second review round (E14): the interval model was still answering yes/no
    questions where the answer is a span, and precedence was read off the wrong
    event stream. Every case here was a wrong verdict before the fix."""

    def write(self, repo, path, body, date):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"write {path}", date=date)

    def fresh(self, tmp_path, name):
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "-q")
        return repo

    def test_a_lockfile_removed_mid_window_leaves_the_rest_uncovered(self, tmp_path):
        # Covered 11-20 → 11-25, unlocked 11-25 → 11-26: overlapping the window at
        # all used to count as covering the whole of it.
        repo = self.fresh(tmp_path, "half-covered")
        (repo / "package.json").write_text('{"name":"app"}')
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-20T10:00:00+00:00")
        (repo / "package-lock.json").unlink()
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "drop the lock", date="2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["package.json"]
        assert finding.verdict is Verdict.INDETERMINATE

    def test_a_lockfile_covering_the_whole_window_clears_the_tree(self, tmp_path):
        # The control: the same shape with no gap must stay clean, or the check
        # above would just be a way of never clearing anything.
        repo = self.fresh(tmp_path, "fully-covered")
        (repo / "package.json").write_text('{"name":"app"}')
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-20T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.unread_trees == []
        assert finding.verdict is Verdict.CLEAN

    def test_a_root_lockfile_does_not_cover_a_directory_it_never_declared(self, tmp_path):
        # Verified against npm 10.9.3: `npm install` in a directory the root does
        # not list as a workspace writes its own lockfile, so the root's lockfile
        # says nothing about it.
        repo = self.fresh(tmp_path, "standalone")
        (repo / "package.json").write_text(
            '{"name":"root","private":true,"workspaces":["packages/*"]}')
        (repo / "apps/standalone").mkdir(parents=True)
        (repo / "apps/standalone/package.json").write_text('{"name":"standalone"}')
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["apps/standalone/package.json"]

    def test_workspace_globs_are_matched_the_way_npm_matches_them(self, tmp_path):
        # `packages/*` covers one level and not two.
        repo = self.fresh(tmp_path, "glob-depth")
        (repo / "package.json").write_text('{"name":"root","workspaces":["packages/*"]}')
        (repo / "packages/api").mkdir(parents=True)
        (repo / "packages/api/package.json").write_text('{"name":"api"}')
        (repo / "packages/group/deep").mkdir(parents=True)
        (repo / "packages/group/deep/package.json").write_text('{"name":"deep"}')
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == [
            "packages/group/deep/package.json"
        ]

    def test_a_deletion_on_one_branch_does_not_clear_another(self, tmp_path):
        # main dropped the manifest before the window; the feature branch still
        # carries it and is still built. Reading main's deletion as the end of
        # every branch's interval reported this clean.
        repo = self.fresh(tmp_path, "branched")
        self.write(repo, "package.json", '{"name":"app"}', "2025-11-01T10:00:00+00:00")
        default = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        git(repo, "checkout", "-q", "-b", "feature")
        git(repo, "commit", "-q", "--allow-empty", "-m", "feature work",
            date="2025-11-25T10:00:00+00:00")
        git(repo, "checkout", "-q", default)
        (repo / "package.json").unlink()
        (repo / "other.txt").write_text("x")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "main drops it", date="2025-11-10T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["package.json"]

    def test_removing_a_shrinkwrap_puts_the_package_lock_back_in_charge(self, tmp_path):
        # The commit that deletes the shrinkwrap never touches package-lock.json,
        # so a log of that path alone never sees the moment it started to matter.
        repo = self.fresh(tmp_path, "unshadowed")
        (repo / "package-lock.json").write_text(lock_json("5.6.1"))
        self.write(repo, "npm-shrinkwrap.json", lock_json("5.6.0"),
                   "2025-11-20T10:00:00+00:00")
        (repo / "npm-shrinkwrap.json").unlink()
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "drop the shrinkwrap",
            date="2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert [e.version for e in finding.exposures] == ["5.6.1"]

    def test_a_rewritten_date_is_a_diagnostic_and_not_lost_evidence(self, tmp_path):
        # A rebase costs no evidence, so it must not widen anything. Treating it
        # as lost evidence put every credential of a rebased repo on the list.
        repo = self.fresh(tmp_path, "rebased-clean")
        (repo / "package-lock.json").write_text(lock_json("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "pin", date="2025-12-25T10:00:00+00:00",
            author_date="2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.warnings == [], finding.warnings
        assert any("diverge" in d for d in finding.diagnostics)


class TestWindowQueryValidation:
    def test_naive_datetime_rejected(self):
        with pytest.raises(ValueError):
            WindowQuery("x", frozenset({"1"}), datetime(2025, 1, 1), WINDOW.window_end)

    def test_inverted_window_rejected(self):
        with pytest.raises(ValueError):
            WindowQuery("x", frozenset({"1"}), WINDOW.window_end, WINDOW.window_start)
