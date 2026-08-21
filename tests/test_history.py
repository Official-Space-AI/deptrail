"""Integration tests for the history walker against synthetic git repos.

Each test builds a real git repo with faked commit dates. The regression
classes at the bottom encode the failure scenarios found by adversarial
review of PR #8 — every one of them produced a wrong verdict before the fix.
"""
import json
import os
import stat
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
        # An incomplete clone is its own kind of not-knowing: a deeper clone is the
        # remedy, and unlike a corrupt lockfile it points at no artifact, so it never
        # widens a rotation list (#20).
        assert any("shallow" in reason for reason in finding.incomplete)
        assert finding.warnings == []

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

class TestForeignLockfilesOverTime:
    """A lockfile this version cannot parse counts while the window was open,
    and only then: holding one committed years earlier against a project denied
    it an all-clear forever."""

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

class TestPrecedenceAndDiagnostics:
    """Precedence was read off the wrong event stream,
    and a harmless observation was being treated as lost evidence."""

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

    def test_a_shrinkwrap_appearing_closes_the_interval(self, tmp_path):
        # npm stops reading the package-lock at that commit, so the pin stops
        # mattering there. The report used to say "still pinned" about a file
        # nothing installs.
        repo = self.fresh(tmp_path, "shadowed-later")
        self.write(repo, "package-lock.json", lock_json("5.6.1"),
                   "2025-11-25T10:00:00+00:00")
        self.write(repo, "npm-shrinkwrap.json", lock_json("5.6.0"),
                   "2025-11-26T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert not finding.exposures[0].still_pinned

    def test_a_foreign_lockfile_added_at_the_closing_instant_counts(self, tmp_path):
        # The window is documented as inclusive on both ends, so the last instant
        # is inside it.
        repo = self.fresh(tmp_path, "last-instant")
        self.write(repo, "yarn.lock", YARN_LOCK, "2025-11-26T23:59:59+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]

    @pytest.mark.skipif(os.name == "nt", reason="Windows forbids newlines in paths")
    def test_a_newline_in_a_path_is_not_a_different_path(self, tmp_path):
        repo = self.fresh(tmp_path, "odd-path")
        (repo / "line\nbreak").mkdir()
        (repo / "line\nbreak/package-lock.json").write_text(lock_json("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "odd path", date="2025-11-25T10:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [e.lockfile_path for e in finding.exposures] == \
            ["line\nbreak/package-lock.json"]
        assert finding.warnings == [], finding.warnings

    def test_a_branch_that_lost_the_merge_conflict_still_testifies(self, tmp_path):
        """E15: git's default history simplification follows one parent of a merge
        that is TREESAME to it, so a branch whose malicious pin lost the conflict
        vanished from the path log — and with the branch deleted after merging, the
        repository reported exit 0 even though CI had built that commit."""
        repo = self.fresh(tmp_path, "lost-merge")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-20T10:00:00+00:00")
        default = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        git(repo, "checkout", "-q", "-b", "feature")
        self.write(repo, "package-lock.json", lock_json("5.6.1"),
                   "2025-11-25T10:00:00+00:00")
        git(repo, "checkout", "-q", default)
        self.write(repo, "package-lock.json", lock_json("5.6.2"),
                   "2025-11-25T11:00:00+00:00")
        git(repo, "merge", "--no-ff", "-X", "ours", "feature", "-m", "merge",
            date="2025-11-25T12:00:00+00:00")
        git(repo, "branch", "-q", "-D", "feature")   # as after a merged-PR cleanup
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED, \
            "the branch's pin is reachable from the merge and CI built it"
        assert [e.version for e in finding.exposures] == ["5.6.1"]

    def test_a_lockfile_introduced_by_a_merge_is_discovered(self, tmp_path):
        """E16: git prints no file list for a merge commit unless asked, so a
        lockfile the merge itself introduced was never discovered — this repository
        has a yarn.lock at HEAD and was reported clean."""
        repo = self.fresh(tmp_path, "evil-merge")
        self.write(repo, "base.txt", "base", "2025-11-01T10:00:00+00:00")
        default = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        git(repo, "checkout", "-q", "-b", "feature")
        self.write(repo, "f.txt", "f", "2025-11-02T10:00:00+00:00")
        git(repo, "checkout", "-q", default)
        self.write(repo, "m.txt", "m", "2025-11-03T10:00:00+00:00")
        git(repo, "merge", "-q", "--no-ff", "--no-commit", "feature")
        (repo / "yarn.lock").write_text(YARN_LOCK)     # present in neither parent
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "merge, and add a lockfile",
            date="2025-11-25T10:00:00+00:00")
        assert lockfile_paths(repo) == []              # npm side unaffected
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]

    def test_a_single_branch_clone_cannot_be_cleared(self, tmp_path):
        # A refspec with no wildcard fetched one branch, so a branch nobody fetched
        # cannot testify. Asserted on the config a real `clone --single-branch` sets.
        from deptrail.history import incomplete_history
        repo = self.fresh(tmp_path, "single-branch")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        assert incomplete_history(repo) == ([], [])
        git(repo, "config", "remote.origin.fetch",
            "+refs/heads/main:refs/remotes/origin/main")
        reasons, notes = incomplete_history(repo)
        assert any("single-branch clone" in r for r in reasons), reasons
        assert scan_repo(repo, WINDOW).verdict is Verdict.INDETERMINATE

    def test_a_partial_clone_that_read_everything_is_still_cleared(self, tmp_path):
        # It has every commit and its blobs arrive on demand. Refusing an all-clear
        # here asserted an unreadability the run itself disproves — every snapshot the
        # verdict rests on was read, and `warnings` is the record of any that were not.
        from deptrail.history import incomplete_history
        repo = self.fresh(tmp_path, "partial")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        git(repo, "config", "remote.origin.promisor", "true")
        git(repo, "config", "remote.origin.partialclonefilter", "blob:none")
        reasons, notes = incomplete_history(repo)
        assert reasons == []
        assert any("partial clone" in n for n in notes), notes
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.CLEAN
        assert any("partial clone" in d for d in finding.diagnostics)

    def test_a_partial_clone_whose_snapshots_cannot_be_read_is_not_cleared(self, tmp_path):
        # The other half: when the blobs really are unavailable, the read failures are
        # what stop the all-clear, and they are recorded per snapshot.
        repo = self.fresh(tmp_path, "partial-broken")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        blob = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD:package-lock.json"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        # Remove the blob the way a promisor clone leaves it: absent from the store.
        loose = repo / ".git/objects" / blob[:2] / blob[2:]
        if loose.exists():
            if os.name == "nt":
                loose.chmod(stat.S_IWRITE)
            loose.unlink()
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert any("unreadable" in w for w in finding.warnings), finding.warnings

    def test_a_full_clone_is_not_called_truncated(self, tmp_path):
        # The control: a wildcard refspec and no promisor must stay clean, or the
        # checks above would just be a way of never clearing anything.
        from deptrail.history import incomplete_history
        repo = self.fresh(tmp_path, "complete")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        git(repo, "config", "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*")
        assert incomplete_history(repo) == ([], [])
        assert scan_repo(repo, WINDOW).verdict is Verdict.CLEAN

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


OPEN_WINDOW = WindowQuery(
    package="chalk",
    malicious_versions=frozenset({"5.6.1"}),
    window_start=datetime.fromisoformat("2025-11-24T00:00:00+00:00"),
    window_end=None,
)


class TestOpenUpperBound:
    """A closed right edge is an assertion; believing it can clear a live repository.

    No registry records when a malicious version stopped being served — measured
    against `registry.npmjs.org`, where an unpublished version keeps its
    `time[version]` and gains no removal timestamp. So `end: null` is the honest
    default, and these tests hold the two verdicts it changes (#23).
    """

    def test_a_pin_that_began_after_a_closed_window_reads_as_clean(self, tmp_path):
        repo = make_repo(tmp_path, "late", [
            ("2025-11-20T10:00:00+00:00", None),
            ("2025-12-10T10:00:00+00:00", "5.6.1"),
        ])
        # The closed window says the artifact was already gone, so this pin could not
        # have installed it.
        assert scan_repo(repo, WINDOW).verdict is Verdict.CLEAN

    def test_the_same_repository_is_exposed_when_the_window_never_closed(self, tmp_path):
        repo = make_repo(tmp_path, "late", [
            ("2025-11-20T10:00:00+00:00", None),
            ("2025-12-10T10:00:00+00:00", "5.6.1"),
        ])
        finding = scan_repo(repo, OPEN_WINDOW)
        # Nobody recorded a removal, so "it was gone by December" is a claim, not a
        # fact — and the tool must not clear a repository on a claim.
        assert finding.verdict is Verdict.EXPOSED
        assert [e.version for e in finding.exposures] == ["5.6.1"]

    def test_an_open_window_still_excludes_what_ended_before_it_opened(self, tmp_path):
        repo = make_repo(tmp_path, "early", [
            ("2025-10-01T10:00:00+00:00", "5.6.1"),
            ("2025-10-05T10:00:00+00:00", "5.6.0"),
        ])
        # Open on the right, not on the left: a pin that was gone before the malicious
        # version existed is not exposure, and an open end must not turn into "always".
        assert scan_repo(repo, OPEN_WINDOW).verdict is Verdict.CLEAN

    def test_a_pin_still_in_place_is_exposed_under_an_open_window(self, tmp_path):
        repo = make_repo(tmp_path, "still", [
            ("2025-11-25T10:00:00+00:00", "5.6.1"),
        ])
        finding = scan_repo(repo, OPEN_WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.exposures[0].still_pinned

    def test_a_foreign_lockfile_added_after_a_closed_window_is_not_judged(self, tmp_path):
        repo = tmp_path / "yarnlate"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "README.md").write_text("x")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init", date="2025-11-20T10:00:00+00:00")
        (repo / "yarn.lock").write_text('# yarn lockfile v1\n\n"chalk@^5.6.0":\n  version "5.6.1"\n')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "yarn", date="2025-12-10T10:00:00+00:00")
        # The tree that cannot be read only matters if it existed while the artifact
        # was installable. Under a closed window this one arrived afterwards.
        assert scan_repo(repo, WINDOW).unread_trees == []

    def test_the_same_foreign_lockfile_is_unread_under_an_open_window(self, tmp_path):
        repo = tmp_path / "yarnlate"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "README.md").write_text("x")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init", date="2025-11-20T10:00:00+00:00")
        (repo / "yarn.lock").write_text('# yarn lockfile v1\n\n"chalk@^5.6.0":\n  version "5.6.1"\n')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "yarn", date="2025-12-10T10:00:00+00:00")
        finding = scan_repo(repo, OPEN_WINDOW)
        # With no recorded removal, a December tree was inside the window too — and it
        # is a tree whose versions this tool cannot read, so it must not be cleared.
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]

    def test_a_foreign_lockfile_deleted_at_the_first_instant_is_not_unread(self, tmp_path):
        repo = tmp_path / "edge"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "yarn.lock").write_text('# yarn lockfile v1\n')
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "yarn", date="2025-11-20T10:00:00+00:00")
        (repo / "yarn.lock").unlink()
        git(repo, "add", "-A")
        # Deleted at the window's very first instant: it was not there while the
        # artifact was installable, so it says nothing. A strict comparison here made
        # the repository INDETERMINATE and moved the exit code from 0 to 2.
        git(repo, "commit", "-qm", "drop", date="2025-11-24T00:00:00+00:00")
        for query in (WINDOW, OPEN_WINDOW):
            finding = scan_repo(repo, query)
            assert finding.unread_trees == [], query.window_end
            assert finding.verdict is Verdict.CLEAN


class TestRowsTheParserCouldNotRead:
    """A parser may read most of a lockfile and have to give up on a few rows
    (``LockfileModel.unread``). Those rows may pin anything, so the snapshot warns and
    cannot end an interval; the rows it did read are still judged. No npm lockfile
    produces such a model, so the parser is stood in for here."""

    @pytest.fixture
    def parser_that_leaves_rows_unread(self, monkeypatch):
        import deptrail.history as history
        real = history.parse_lockfile

        def parse(text):
            model = real(text)
            if '"x-unread"' in text:
                model.unread.append("weird@key: no name@version separator")
            return model
        monkeypatch.setattr(history, "parse_lockfile", parse)

    @staticmethod
    def lock_with_unread_rows(chalk_version):
        data = json.loads(lock_json(chalk_version))
        data["x-unread"] = True
        return json.dumps(data)

    def test_a_snapshot_with_unread_rows_warns_and_is_not_clean(
            self, tmp_path, parser_that_leaves_rows_unread):
        repo = tmp_path / "partly"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package-lock.json").write_text(self.lock_with_unread_rows("5.6.0"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "pin", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert not finding.exposed
        assert finding.verdict is Verdict.INDETERMINATE
        assert len(finding.warnings) == 1
        assert "1 package row(s) could not be read" in finding.warnings[0]
        assert "weird@key" in finding.warnings[0]

    def test_the_rows_it_did_read_are_still_judged(
            self, tmp_path, parser_that_leaves_rows_unread):
        repo = tmp_path / "partly-exposed"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package-lock.json").write_text(self.lock_with_unread_rows("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "pin", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed and finding.verdict is Verdict.EXPOSED
        assert finding.exposures[0].chain == ("express", "debug", "chalk")
        assert finding.warnings, "and the unread row is still on the record"

    def test_a_later_snapshot_with_unread_rows_cannot_end_the_interval(
            self, tmp_path, parser_that_leaves_rows_unread):
        repo = make_repo(tmp_path, "closing", [("2025-11-25T12:00:00+00:00", "5.6.1")])
        (repo / "package-lock.json").write_text(self.lock_with_unread_rows("5.6.0"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "bump, partly read", date="2025-11-26T12:00:00+00:00")
        (repo / "package-lock.json").write_text(lock_json("5.6.0"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "bump, fully read", date="2025-11-27T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        until = finding.exposures[0].until
        assert until == _parse_iso("2025-11-27T12:00:00+00:00"), \
            "the partly read snapshot may still pin 5.6.1 in a row nobody could read"

    def test_the_evidence_chain_comes_from_a_registry_instance(self, tmp_path, monkeypatch):
        """With two instances of the bad version, one from git nested under another
        package, the chain must belong to the one the advisory is about."""
        import deptrail.history as history
        from deptrail.lockfile import SOURCE, InstalledPackage
        real = history.parse_lockfile

        def parse(text):
            model = real(text)
            model.packages.insert(0, InstalledPackage(
                "chalk", "5.6.1", "node_modules/tarball-parent/node_modules/chalk",
                origin=SOURCE))
            return model
        monkeypatch.setattr(history, "parse_lockfile", parse)
        repo = make_repo(tmp_path, "two-chalks", [("2025-11-25T12:00:00+00:00", "5.6.1")])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].chain == ("express", "debug", "chalk")
