"""Integration tests for the history walker against synthetic git repos.

Each test builds a real git repo with faked commit dates. The regression
classes at the bottom encode the failure scenarios found by adversarial
review of PR #8 — every one of them produced a wrong verdict before the fix.
"""
import base64
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


PNPM_HEAD = """\
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      express:
        specifier: ^4.19.0
        version: 4.19.2

packages:

  express@4.19.2:
    resolution: {integrity: sha512-a}

  debug@4.3.5:
    resolution: {integrity: sha512-b}
"""


def pnpm_lock(chalk_version: str | None) -> str:
    """The pnpm twin of ``lock_json``: express -> debug -> chalk, chalk optional."""
    if chalk_version is None:
        return PNPM_HEAD + """
snapshots:

  express@4.19.2:
    dependencies:
      debug: 4.3.5

  debug@4.3.5: {}
"""
    return PNPM_HEAD + f"""
  chalk@{chalk_version}:
    resolution: {{integrity: sha512-c}}

snapshots:

  express@4.19.2:
    dependencies:
      debug: 4.3.5

  debug@4.3.5:
    dependencies:
      chalk: {chalk_version}

  chalk@{chalk_version}: {{}}
"""


class TestPnpmTrees:
    """pnpm-lock.yaml is parsed and judged like npm's lockfiles (#17 part 2c)."""

    @staticmethod
    def pnpm_repo(tmp_path, name, states):
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "-q")
        for i, (date, version) in enumerate(states):
            (repo / "pnpm-lock.yaml").write_text(pnpm_lock(version))
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", f"chore: state {i}", date=date)
        return repo

    def test_a_pinned_bad_version_is_an_exposure_with_its_chain(self, tmp_path):
        repo = self.pnpm_repo(tmp_path, "pnpm-exposed", [
            ("2025-11-25T12:00:00+00:00", "5.6.1"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.unread_trees == [] and finding.warnings == []
        exposure = finding.exposures[0]
        assert exposure.lockfile_path == "pnpm-lock.yaml"
        assert exposure.chain == ("express", "debug", "chalk")
        assert exposure.still_pinned

    def test_a_version_bump_ends_the_interval(self, tmp_path):
        repo = self.pnpm_repo(tmp_path, "pnpm-bumped", [
            ("2025-11-25T12:00:00+00:00", "5.6.1"),
            ("2025-11-26T12:00:00+00:00", "5.6.0"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].until == _parse_iso("2025-11-26T12:00:00+00:00")

    def test_a_clean_pnpm_tree_is_clean(self, tmp_path):
        repo = self.pnpm_repo(tmp_path, "pnpm-clean", [
            ("2025-11-25T12:00:00+00:00", "5.6.0"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.CLEAN
        assert finding.lockfiles_seen == 1, "clean because judged, not because unseen"

    def test_a_truncated_lockfile_cannot_end_the_interval_or_read_clean(self, tmp_path):
        """YAML is prefix-valid: a lockfile cut after its importer block still parses,
        with the pins recorded and every row gone. Reading that as "pins nothing"
        closed the interval below at the truncating commit, silently."""
        repo = self.pnpm_repo(tmp_path, "pnpm-truncated", [
            ("2025-11-25T12:00:00+00:00", "5.6.1"),
        ])
        (repo / "pnpm-lock.yaml").write_text(PNPM_HEAD.split("packages:")[0])
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "truncate", date="2025-11-26T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].until is None, "the truncated snapshot proves nothing"
        assert finding.exposures[0].still_pinned
        assert len(finding.warnings) == 1
        assert "holds no row for" in finding.warnings[0]

    def test_a_lockfile_that_will_not_parse_warns_and_is_not_clean(self, tmp_path):
        repo = tmp_path / "pnpm-broken"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "pnpm-lock.yaml").write_text("lockfileVersion: [\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "bad", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert finding.warnings and "unreadable" in finding.warnings[0]
        assert finding.unread_trees == []

    def test_a_row_the_splitter_refuses_keeps_the_tree_from_reading_clean(self, tmp_path):
        repo = tmp_path / "pnpm-partly"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "pnpm-lock.yaml").write_text(pnpm_lock("5.6.0") + """
  /stray@1.0.0:
    resolution: {integrity: sha512-s}
""")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "lock", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert len(finding.warnings) == 1
        assert "1 package row(s) could not be read" in finding.warnings[0]
        assert "/stray@1.0.0" in finding.warnings[0]

    def test_an_empty_pnpm_lockfile_pinned_nothing_and_is_clean(self, tmp_path):
        repo = tmp_path / "pnpm-empty"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "lock", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.CLEAN
        assert finding.lockfiles_seen == 1, "clean because judged, not because unseen"

    def test_a_shrinkwrap_beside_it_does_not_silence_a_pnpm_lockfile(self, tmp_path):
        """npm's precedence rule is npm's: a shrinkwrap silences package-lock.json
        because npm itself ignores that file, and nothing else."""
        repo = tmp_path / "shrinkwrap-beside-pnpm"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "npm-shrinkwrap.json").write_text(lock_json("5.6.0"))
        (repo / "pnpm-lock.yaml").write_text(pnpm_lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "both", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert {e.lockfile_path for e in finding.exposures} == {"pnpm-lock.yaml"}

    def test_a_nested_pnpm_lockfile_is_judged_by_its_basename(self, tmp_path):
        repo = tmp_path / "pnpm-nested"
        repo.mkdir()
        (repo / "packages/api").mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / "packages/api/pnpm-lock.yaml").write_text(pnpm_lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "nested", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.exposures[0].lockfile_path == "packages/api/pnpm-lock.yaml"
        assert finding.warnings == []

    def test_npm_and_pnpm_lockfiles_in_one_repository_both_testify(self, tmp_path):
        """Neither shadows the other: each is what its own tool installed."""
        repo = tmp_path / "both"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package-lock.json").write_text(lock_json("5.6.1"))
        (repo / "pnpm-lock.yaml").write_text(pnpm_lock("5.6.1"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "both", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.lockfiles_seen == 2
        assert {e.lockfile_path for e in finding.exposures} == {
            "package-lock.json", "pnpm-lock.yaml"}


BERRY_HEAD = """\
# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    express: "npm:^4.19.0"
  languageName: unknown
  linkType: soft

"express@npm:^4.19.0":
  version: 4.19.2
  resolution: "express@npm:4.19.2"
  dependencies:
    debug: "npm:^4.3.4"
  languageName: node
  linkType: hard
"""


def berry_lock(chalk_version: str | None) -> str:
    """The Berry twin of ``lock_json``: express -> debug -> chalk, chalk optional."""
    if chalk_version is None:
        return BERRY_HEAD + """
"debug@npm:^4.3.4":
  version: 4.3.5
  resolution: "debug@npm:4.3.5"
  languageName: node
  linkType: hard
"""
    return BERRY_HEAD + f"""
"debug@npm:^4.3.4":
  version: 4.3.5
  resolution: "debug@npm:4.3.5"
  dependencies:
    chalk: "npm:^5.6.0"
  languageName: node
  linkType: hard

"chalk@npm:^5.6.0":
  version: {chalk_version}
  resolution: "chalk@npm:{chalk_version}"
  languageName: node
  linkType: hard
"""


class TestYarnTrees:
    """yarn.lock is one basename for two formats; the blob's content decides, and a
    Yarn 1 blob is an unread tree only while the window was open (#87)."""

    @staticmethod
    def yarn_repo(tmp_path, name, states):
        """states: (date, content) pairs written to yarn.lock."""
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "-q")
        for i, (date, content) in enumerate(states):
            (repo / "yarn.lock").write_text(content)
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", f"chore: state {i}", date=date)
        return repo

    def test_a_berry_tree_is_judged_with_its_chain(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "berry-exposed", [
            ("2025-11-25T12:00:00+00:00", berry_lock("5.6.1")),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.unread_trees == [] and finding.warnings == []
        assert finding.exposures[0].lockfile_path == "yarn.lock"
        assert finding.exposures[0].chain == ("express", "debug", "chalk")

    def test_a_clean_berry_tree_is_clean(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "berry-clean", [
            ("2025-11-25T12:00:00+00:00", berry_lock("5.6.0")),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.CLEAN
        assert finding.lockfiles_seen == 1, "clean because judged, not because unseen"

    def test_a_version_bump_ends_the_interval(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "berry-bumped", [
            ("2025-11-25T12:00:00+00:00", berry_lock("5.6.1")),
            ("2025-11-26T12:00:00+00:00", berry_lock("5.6.0")),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].until == _parse_iso("2025-11-26T12:00:00+00:00")

    def test_a_truncated_berry_snapshot_warns_and_cannot_close(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "berry-truncated", [
            ("2025-11-25T12:00:00+00:00", berry_lock("5.6.1")),
            ("2025-11-26T12:00:00+00:00", BERRY_HEAD.split('"app@workspace')[0]),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].until is None, "a truncated snapshot proves nothing"
        assert finding.warnings and "workspace entry" in finding.warnings[0]

    def test_a_yarn_one_blob_inside_the_window_is_an_unread_tree(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "v1-live", [
            ("2025-11-25T12:00:00+00:00", YARN_LOCK),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]
        assert "Yarn 1" in finding.unread_trees[0].reason
        assert finding.warnings == [], "an unread tree is not lost evidence"

    def test_a_yarn_one_era_outside_the_window_is_not_held_against_the_tree(self, tmp_path):
        """babel left Yarn 1 years before any 2025 incident; the migration must not
        deny it an all-clear forever."""
        repo = self.yarn_repo(tmp_path, "migrated", [
            ("2020-06-01T12:00:00+00:00", YARN_LOCK),
            ("2021-01-01T12:00:00+00:00", berry_lock("5.6.0")),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.unread_trees == []
        assert finding.verdict is Verdict.CLEAN

    def test_a_yarn_one_era_covering_the_window_is_held_against_the_tree(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "migrated-late", [
            ("2025-11-24T12:00:00+00:00", YARN_LOCK),
            ("2025-11-26T12:00:00+00:00", berry_lock("5.6.0")),
        ])
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]
        assert finding.verdict is Verdict.INDETERMINATE

    def test_a_yarn_one_successor_cannot_end_a_berry_interval(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "downgraded", [
            ("2025-11-25T12:00:00+00:00", berry_lock("5.6.1")),
            ("2025-11-26T12:00:00+00:00", YARN_LOCK),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].until is None, "a blob we cannot read proves nothing"

    def test_a_berry_file_with_a_stray_v1_header_is_still_read(self, tmp_path):
        """Routing on the header alone skipped a readable file's evidence wholesale."""
        repo = self.yarn_repo(tmp_path, "stray-header", [
            ("2025-11-25T12:00:00+00:00",
             "# yarn lockfile v1\n" + berry_lock("5.6.1")),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.EXPOSED
        assert finding.unread_trees == []

    def test_a_pre_window_sibling_cannot_discharge_an_in_window_dialect(self, tmp_path):
        """The segment ends at the first *descendant* whose snapshot differs. A
        pre-window Berry attempt on a sibling branch is not a descendant of the
        in-window Yarn 1 commit; letting it close the segment discharged the witness
        and read the repository CLEAN. The rebased-looking author/committer split on
        the v1 commit pins the emission order that made that reachable."""
        import subprocess
        repo = tmp_path / "sibling"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "yarn.lock").write_text(YARN_LOCK)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "base v1", date="2025-11-01T12:00:00+00:00")
        default = subprocess.run(["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
                                 check=True, capture_output=True, text=True).stdout.strip()
        git(repo, "checkout", "-q", "-b", "berry-try")
        (repo / "yarn.lock").write_text(berry_lock("5.6.0"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "try berry", date="2025-11-20T12:00:00+00:00")
        git(repo, "checkout", "-q", default)
        (repo / "yarn.lock").write_text(YARN_LOCK + "\n# still yarn 1\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "v1 in window",
            author_date="2025-11-25T12:00:00+00:00")  # committer date = now: rebased shape
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
                        "merge", "-q", "--no-ff", "--no-commit", "berry-try"],
                       capture_output=True)  # both sides touched the file: conflict expected
        (repo / "yarn.lock").write_text(YARN_LOCK + "\n# still yarn 1\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "merge, v1 wins", date="2025-11-28T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]

    def test_the_witness_is_the_first_in_window_sighting(self, tmp_path):
        """org.py fetches workflow evidence at exactly this commit, so which sighting
        the witness names is load-bearing, not cosmetic."""
        import subprocess
        repo = self.yarn_repo(tmp_path, "two-sightings", [
            ("2025-11-24T12:00:00+00:00", YARN_LOCK),
        ])
        first = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                               check=True, capture_output=True, text=True).stdout.strip()
        (repo / "yarn.lock").write_text(YARN_LOCK + "\n# updated\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "still v1", date="2025-11-25T12:00:00+00:00")
        (repo / "yarn.lock").write_text(berry_lock("5.6.0"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "berry", date="2025-11-26T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert [t.path for t in finding.unread_trees] == ["yarn.lock"]
        assert finding.unread_trees[0].commit == first

    def test_a_yarn_lock_that_is_neither_format_warns(self, tmp_path):
        repo = self.yarn_repo(tmp_path, "garbage", [
            ("2025-11-25T12:00:00+00:00", "not a lockfile at all\n"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert finding.warnings and "unreadable" in finding.warnings[0]
        assert finding.unread_trees == []


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

    def test_a_pnpm_v3_shrinkwrap_is_still_only_recognised(self, tmp_path):
        repo = tmp_path / "pnpm3"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "shrinkwrap.yaml").write_text("shrinkwrapVersion: 3\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "lock", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.verdict is Verdict.INDETERMINATE
        assert [t.path for t in finding.unread_trees] == ["shrinkwrap.yaml"]
        assert "pnpm (v3 and earlier)" in finding.unread_trees[0].reason

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
        assert lockfile_paths(repo) == ["yarn.lock"]   # discovered as a parsed path now
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

    def origin_with_two_branches(self, tmp_path, name):
        """A bare origin holding `main` and `release/1.x`, the #27 shape's remote."""
        origin = tmp_path / f"{name}-origin.git"
        git(tmp_path, "init", "-q", "--bare", str(origin))
        work = self.fresh(tmp_path, f"{name}-work")
        self.write(work, "package-lock.json", lock_json(None),
                   "2025-11-20T10:00:00+00:00")
        git(work, "branch", "-M", "main")
        git(work, "remote", "add", "origin", str(origin))
        git(work, "push", "-q", "origin", "main")
        git(work, "checkout", "-qb", "release/1.x")
        self.write(work, "package-lock.json", lock_json("5.6.1"),
                   "2025-11-25T10:00:00+00:00")
        # A second commit so the branch can be rewound to a tip that is genuinely
        # nobody's ref — rewinding to the first would land on main's own tip.
        self.write(work, "NOTES.md", "release notes\n", "2025-11-25T11:00:00+00:00")
        git(work, "push", "-q", "origin", "release/1.x")
        git(origin, "symbolic-ref", "HEAD", "refs/heads/main")
        return origin

    def rewind(self, tmp_path, origin, branch):
        """Point a remote branch at its parent, so its tip is a commit a clone holds
        but no ref of its own names."""
        parent = subprocess.run(
            ["git", "-C", str(origin), "rev-parse", f"refs/heads/{branch}~1"],
            check=True, capture_output=True, text=True).stdout.strip()
        git(origin, "update-ref", f"refs/heads/{branch}", parent)

    def test_a_one_branch_fetch_is_named_by_asking_the_remote(self, tmp_path):
        """#27: `git init` + `fetch origin main` kept the wildcard refspec, was not
        shallow and had no promisor, so every local check passed and the repository
        was cleared at exit 0 — with the exposing pin sitting on a branch nobody
        fetched. Only the remote's own ref list settles it.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "onebranch")
        repo = self.fresh(tmp_path, "onebranch-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        reasons, _ = incomplete_history(repo)
        assert any("release/1.x" in r for r in reasons), reasons
        assert scan_repo(repo, WINDOW).verdict is Verdict.INDETERMINATE

    def test_a_checkout_that_fetched_every_head_is_not_penalised(self, tmp_path):
        """The shape that makes the local signals useless: `actions/checkout` with
        `fetch-depth: 0` is `init` plus a wildcard `fetch`, so it holds every branch
        while leaving no `origin/HEAD` and the same wildcard refspec as the case
        above. Penalising it would refuse an all-clear for the recommended CI
        configuration.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "ciwide")
        repo = self.fresh(tmp_path, "ciwide-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "--no-tags", "--prune", "origin",
            "+refs/heads/*:refs/remotes/origin/*")
        git(repo, "checkout", "-qb", "main", "origin/main")
        assert incomplete_history(repo) == ([], [])
        # And it still sees the exposure the one-branch fetch could not.
        assert scan_repo(repo, WINDOW).verdict is Verdict.EXPOSED

    def test_a_branch_fetched_under_another_name_is_not_called_missing(self, tmp_path):
        """Coverage is about what the walk can reach, not what the refs are called:
        a branch fetched into a ref of a different name is still walked, so naming it
        missing would be a reason with no cost behind it.

        What it pins is the tip set, not the reachability query behind it: the
        branch is held at the identical commit, so the fast path answers it. The
        remote-tracking ref the wildcard refspec writes anyway is deleted, or the
        branch would be held under its ordinary name and the naming would not be
        tested at all.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "renamed")
        repo = self.fresh(tmp_path, "renamed-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin",
            "+refs/heads/main:refs/remotes/origin/main",
            "+refs/heads/release/1.x:refs/remotes/origin/kept-under-another-name")
        git(repo, "update-ref", "-d", "refs/remotes/origin/release/1.x")
        git(repo, "checkout", "-qb", "main", "origin/main")
        assert [r for r in incomplete_history(repo)[0] if "release/1.x" in r] == []

    def test_a_planted_ssh_command_is_not_run_by_the_coverage_check(self, tmp_path,
                                                                     monkeypatch):
        """The repository being scanned may be the compromised one, so its config is
        input and not settings: `core.sshCommand` planted there is executed by
        `ls-remote` (measured), and `-c` on the command line outranks it.
        """
        from deptrail.history import _remote_heads
        # The suite blocks ssh outright, which would refuse this before the planted
        # command could run and leave the assertion passing for the wrong reason.
        monkeypatch.delenv("GIT_ALLOW_PROTOCOL", raising=False)
        marker = tmp_path / "executed"
        repo = self.fresh(tmp_path, "hostile")
        git(repo, "remote", "add", "origin", "ssh://git@example.invalid/x.git")
        git(repo, "config", "core.sshCommand", f"touch {marker} ; false")
        assert _remote_heads(repo) is None      # unreachable, as it should be
        assert not marker.exists()

    def test_a_planted_upload_pack_is_not_run_by_the_coverage_check(self, tmp_path,
                                                                    monkeypatch):
        """The second measured command in the same config, and the reason the query
        stopped reading that config at all: `remote.origin.uploadpack` is executed
        for a local remote, and overriding it on the command line did not stop it.
        """
        from deptrail.history import _remote_heads
        monkeypatch.delenv("GIT_ALLOW_PROTOCOL", raising=False)
        origin = self.origin_with_two_branches(tmp_path, "uploadpack")
        marker = tmp_path / "upload-pack-ran"
        repo = self.fresh(tmp_path, "uploadpack-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "config", "remote.origin.uploadpack", f"touch {marker} ; false")
        assert _remote_heads(repo) is not None   # the URL still answers
        assert not marker.exists()

    def test_a_detached_head_covers_the_tip_it_holds(self, tmp_path):
        """`_refs` walks HEAD, so a detached checkout can be the only thing holding
        a branch tip — and leaving HEAD out of the coverage check reported a
        complete clone as missing every branch it had.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "detached")
        repo = tmp_path / "detached-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        git(repo, "checkout", "-q", "--detach", "origin/release/1.x")
        for ref in ("refs/remotes/origin/release/1.x", "refs/remotes/origin/main",
                    "refs/remotes/origin/HEAD"):
            git(repo, "update-ref", "-d", ref)
        git(repo, "branch", "-D", "main")
        assert [r for r in incomplete_history(repo)[0] if "release/1.x" in r] == []

    def test_a_relative_remote_path_still_resolves(self, tmp_path):
        """The query runs from a neutral directory, so a URL written relative to the
        clone has to be resolved while it still means something.
        """
        from deptrail.history import _remote_heads
        origin = self.origin_with_two_branches(tmp_path, "relative")
        repo = self.fresh(tmp_path, "relative-clone")
        git(repo, "remote", "add", "origin", f"../{origin.name}")
        heads = _remote_heads(repo)
        assert heads is not None and "release/1.x" in heads, heads

    def test_an_unborn_head_does_not_lose_the_branches_the_clone_has(self, tmp_path):
        """A checkout that fetched and never checked out has no HEAD to resolve.
        Feeding `^HEAD` to rev-list anyway made the whole query fatal, and a fatal
        query reads as "nothing is reachable" — so a clone holding every branch was
        told it was missing them.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "unborn")
        repo = self.fresh(tmp_path, "unborn-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*")
        # The remote is rewound to a commit this clone holds but no ref points at,
        # so the tip has to be asked about rather than matched — which is the path
        # `^HEAD` was fatal on.
        self.rewind(tmp_path, origin, "release/1.x")
        assert incomplete_history(repo)[0] == []

    def test_one_broken_ref_does_not_condemn_every_other_branch(self, tmp_path):
        """A pruned or half-fetched clone can hold a ref whose object is gone. Naming
        such a ref as an exclusion made rev-list fatal, and the same "fatal means
        nothing is reachable" rule then reported every diverged branch as missing.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "brokenref")
        repo = tmp_path / "brokenref-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        broken = repo / ".git/refs/remotes/origin/pruned"
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.write_text("0" * 39 + "1\n")
        # Same reason as above: a tip that must be asked about, not matched.
        self.rewind(tmp_path, origin, "release/1.x")
        assert incomplete_history(repo)[0] == []

    def test_a_branch_called_head_is_not_counted_as_covered(self, tmp_path):
        """`_refs` drops every ref whose name ends in `/HEAD`, taking it for the
        alias it usually is — so a remote branch actually *called* `HEAD` is fetched,
        never walked, and used to be counted here as held. A pin on it was reported
        at exit 0, which is #27 again through the check written to close it.
        """
        from deptrail.history import _remote_heads, _heads_not_here, _refs
        origin = self.origin_with_two_branches(tmp_path, "headname")
        work = tmp_path / "headname-work"
        git(work, "push", "-q", "origin", "release/1.x:refs/heads/carrier")
        tip = subprocess.run(
            ["git", "-C", str(work), "rev-parse", "refs/heads/release/1.x"],
            check=True, capture_output=True, text=True).stdout.strip()
        # Written by hand, and only once the object is there: git will not create a
        # branch under this name, and a ref naming an absent object breaks the push.
        (origin / "refs/heads/HEAD").write_text(tip + "\n")
        git(origin, "update-ref", "-d", "refs/heads/carrier")
        # Only this ref may hold that commit, or an ordinary branch would cover it
        # and the dropped name would never be the deciding one.
        git(origin, "update-ref", "-d", "refs/heads/release/1.x")

        repo = self.fresh(tmp_path, "headname-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*")
        git(repo, "checkout", "-qb", "main", "origin/main")
        assert "refs/remotes/origin/HEAD" not in _refs(repo)
        assert "HEAD" in _heads_not_here(repo, _remote_heads(repo))

    def test_a_ref_naming_an_absent_object_does_not_prove_coverage(self, tmp_path):
        """A pruned or interrupted fetch leaves a ref pointing at an object the clone
        does not have. Matching an advertised tip against one of those said the
        branch was held by a commit nobody has.
        """
        from deptrail.history import _remote_heads, _heads_not_here
        origin = self.origin_with_two_branches(tmp_path, "leftover")
        repo = self.fresh(tmp_path, "leftover-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        tip = subprocess.run(
            ["git", "-C", str(origin), "rev-parse", "refs/heads/release/1.x"],
            check=True, capture_output=True, text=True).stdout.strip()
        leftover = repo / ".git/refs/remotes/origin/release-leftover"
        leftover.parent.mkdir(parents=True, exist_ok=True)
        leftover.write_text(tip + "\n")
        assert "release/1.x" in _heads_not_here(repo, _remote_heads(repo))

    def test_an_operator_may_forbid_every_transport(self, tmp_path, monkeypatch):
        """Empty is git's own way of saying "allow nothing", so it is a setting and
        not an absence — read as unset, the strictest narrowing became the broadest
        list.
        """
        from deptrail.history import _remote_heads
        origin = self.origin_with_two_branches(tmp_path, "forbidden")
        repo = self.fresh(tmp_path, "forbidden-clone")
        git(repo, "remote", "add", "origin", str(origin))
        # Set last: the fixtures above are built with git, which would be forbidden
        # its own transports too.
        monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "")
        assert _remote_heads(repo) is None

    def test_a_branch_pointing_at_an_annotated_tag_is_judged_by_its_commit(
            self, tmp_path):
        """`ls-remote` advertises such a branch twice: the tag object, then the
        commit it peels to. Keeping the tag object made its id match nothing local
        while `rev-list` answered about the commit — so a branch the walk cannot
        reach at all came back covered.
        """
        from deptrail.history import _remote_heads, _heads_not_here
        origin = self.origin_with_two_branches(tmp_path, "tagged")
        work = tmp_path / "tagged-work"
        git(work, "checkout", "-q", "-b", "aside")
        self.write(work, "aside.md", "aside\n", "2025-11-26T10:00:00+00:00")
        git(work, "tag", "-a", "atag", "-m", "annotated")
        git(work, "push", "-q", "origin", "atag")
        tag = subprocess.run(["git", "-C", str(work), "rev-parse", "atag"],
                             check=True, capture_output=True, text=True).stdout.strip()
        # Written by hand: git refuses to point a branch at a tag object itself.
        (origin / "refs/heads/tagbranch").write_text(tag + "\n")

        repo = self.fresh(tmp_path, "tagged-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "main", "--tags")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        heads = _remote_heads(repo)
        # release/1.x is missing too, and honestly so — this clone fetched only main.
        assert "tagbranch" in _heads_not_here(repo, heads), heads

    def test_a_repository_named_by_the_environment_cannot_be_scanned_instead(
            self, tmp_path, monkeypatch):
        """`GIT_DIR` outranks both the directory a command runs in and any ceiling
        set for it. Inherited from a scan launched inside a hook, it put the query
        back in the repository under investigation, whose planted `core.sshCommand`
        then ran.
        """
        from deptrail.history import _remote_heads
        monkeypatch.delenv("GIT_ALLOW_PROTOCOL", raising=False)
        marker = tmp_path / "ran-from-git-dir"
        repo = self.fresh(tmp_path, "gitdir-hostile")
        git(repo, "remote", "add", "origin", "ssh://git@example.invalid/x.git")
        git(repo, "config", "core.sshCommand", f"touch {marker} ; false")
        monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
        assert _remote_heads(repo) is None
        assert not marker.exists()

    def test_a_credential_in_the_url_is_never_carried_into_the_query(self, tmp_path,
                                                                     monkeypatch):
        """A clone written by CI can carry a token in its origin URL, and keeping it
        out of *this* code's arguments does not keep it out of `ps`: git hands the
        whole URL to its own transport helper (`git remote-https origin <url>`,
        seen in GIT_TRACE). So the credential is dropped instead — where the
        operator's credential helper knows the host the query still authenticates,
        and where it does not, coverage comes back unverified.
        """
        from deptrail import history
        secret = "https://x-access-token:s3cr3t-token@example.invalid/x.git"
        repo = self.fresh(tmp_path, "tokened")
        git(repo, "remote", "add", "origin", secret)
        # Nothing from the userinfo survives over https: a token in the username
        # with an empty password is the documented spelling, and git sends it as
        # Basic auth. Over ssh the username is an account, and it does survive.
        assert history._remote_url(repo, "origin") == "https://example.invalid/x.git"
        seen: list[list[str]] = []
        real = history.subprocess.run

        def record(args, **kwargs):
            if isinstance(args, list):
                seen.append(args)
            return real(args, **kwargs)

        monkeypatch.setattr(history.subprocess, "run", record)
        history._remote_heads(repo)
        assert seen, "no command ran"
        assert not any("s3cr3t-token" in part for args in seen for part in args), seen

    def test_a_url_git_config_would_mangle_is_still_read(self, tmp_path):
        """The URL is written into a config file, where a backslash is an escape and
        `#` or `;` start a comment — a Windows path or a path with either character
        was truncated or made the file unparseable, and the coverage answer was lost
        with it.
        """
        from deptrail.history import _remote_heads
        origin = self.origin_with_two_branches(tmp_path, "awkward")
        awkward = tmp_path / "we#ird;dir"
        awkward.mkdir()
        moved = awkward / origin.name
        origin.rename(moved)
        repo = self.fresh(tmp_path, "awkward-clone")
        git(repo, "remote", "add", "origin", str(moved))
        heads = _remote_heads(repo)
        assert heads is not None and "release/1.x" in heads, heads

    def test_a_permissive_environment_cannot_widen_the_transports(self, tmp_path,
                                                                  monkeypatch):
        """The allowlist is intersected with the environment, not defaulted to it: an
        operator may narrow the transports, but a permissive value must not put
        `ext::` — whose command comes from the repository under investigation — back
        within reach.
        """
        from deptrail.history import _remote_heads
        monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "https:ssh:ext")
        marker = tmp_path / "widened"
        payload = tmp_path / "payload.sh"
        payload.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        payload.chmod(0o755)
        repo = self.fresh(tmp_path, "widened-clone")
        git(repo, "remote", "add", "origin", f"ext::{payload}")
        git(repo, "config", "protocol.ext.allow", "always")
        assert _remote_heads(repo) is None
        assert not marker.exists()

    def test_an_exotic_transport_is_refused_even_if_the_repo_re_enables_it(
            self, tmp_path, monkeypatch):
        """`ext::` runs the command named in the URL, and the repository under
        investigation is where the URL comes from.

        This pins the outcome, not the mechanism: measured on git 2.x it holds on
        git's own default with the allowlist removed, so it fails only if both locks
        go. That is the assertion worth keeping — this must never execute — and the
        allowlist is the one of the two this project controls.
        """
        from deptrail.history import _remote_heads
        # Same trap: with the suite's own block in place this would pass without the
        # allowlist the code sets for itself.
        monkeypatch.delenv("GIT_ALLOW_PROTOCOL", raising=False)
        marker = tmp_path / "executed-ext"
        # A script, not a quoted shell line: git splits an `ext::` command on
        # whitespace, and the first version of this test planted a payload that
        # `sh` refused to parse — so it passed with the allowlist removed and
        # guarded nothing.
        payload = tmp_path / "payload.sh"
        payload.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        payload.chmod(0o755)
        repo = self.fresh(tmp_path, "hostile-ext")
        git(repo, "remote", "add", "origin", f"ext::{payload}")
        git(repo, "config", "protocol.ext.allow", "always")
        assert _remote_heads(repo) is None
        assert not marker.exists()

    def test_a_clone_that_fell_behind_the_remote_is_not_cleared(self, tmp_path):
        """Coverage is about commits, and matching branch names hid that. A clone
        whose `origin/release/1.x` is behind holds the name and not the tip, and
        blessing the name cleared a repository at exit 0 while the pin that mattered
        sat on the remote's own head — the same false all-clear #27 is about, one
        fetch later.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "behind")
        repo = tmp_path / "behind-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        # The remote moves on: the same branch, commits this clone has never seen.
        ahead = tmp_path / "behind-ahead"
        git(tmp_path, "clone", "-q", str(origin), str(ahead))
        git(ahead, "checkout", "-q", "release/1.x")
        self.write(ahead, "package-lock.json", lock_json("5.6.3"),
                   "2025-11-26T10:00:00+00:00")
        git(ahead, "push", "-q", "origin", "release/1.x")
        reasons, _ = incomplete_history(repo)
        assert any("release/1.x" in r for r in reasons), reasons

    def test_a_ref_that_moved_past_the_advertised_tip_still_covers_it(self, tmp_path):
        """The other direction: a clone ahead of the remote reaches the advertised
        tip through its own ref, so it is not accused of a gap it does not have.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "ahead")
        repo = tmp_path / "ahead-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        git(repo, "checkout", "-q", "-b", "local-release", "origin/release/1.x")
        self.write(repo, "package-lock.json", lock_json("5.6.2"),
                   "2025-11-27T10:00:00+00:00")
        # The tracking ref still sits on the advertised tip, and the exact-tip path
        # would answer before the reachability query ran — leaving the branch held
        # only by a ref that has moved past it, which is the case under test.
        git(repo, "update-ref", "-d", "refs/remotes/origin/release/1.x")
        assert incomplete_history(repo)[0] == []

    def test_the_remote_is_asked_once_per_repository(self, tmp_path, monkeypatch):
        """`scan_organization` rebuilds a finding once per advisory package, so the
        one check here that leaves the machine has to be paid for once: a 180-package
        advisory over 200 repositories would otherwise have asked 36,000 times.
        """
        from deptrail import history
        origin = self.origin_with_two_branches(tmp_path, "asked-once")
        repo = tmp_path / "asked-once-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        asked = []
        real = history._remote_heads
        monkeypatch.setattr(history, "_remote_heads",
                            lambda r, name="origin", **kw:
                            (asked.append(r), real(r, name, **kw))[1])
        cache: dict = {}
        for _ in range(3):
            history.incomplete_history(repo, cache)
        assert len(asked) == 1, asked
        # And without a cache each call stands on its own, which is what a lone
        # `scan_repo` needs.
        history.incomplete_history(repo)
        assert len(asked) == 2, asked

    def test_a_remote_not_called_origin_is_still_the_remote(self, tmp_path):
        """Every check that read config spelled the name `origin`, so a clone made
        with `-o upstream` — or on a machine with `clone.defaultRemoteName` set,
        which is one global config line — answered none of them. Measured: the same
        single-branch checkout went from exit 2 to exit 0 on that alone.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "renamed-remote")
        repo = self.fresh(tmp_path, "renamed-remote-clone")
        git(repo, "remote", "add", "upstream", str(origin))
        git(repo, "fetch", "-q", "upstream",
            "+refs/heads/main:refs/remotes/upstream/main")
        git(repo, "checkout", "-qb", "main", "upstream/main")
        git(repo, "config", "remote.upstream.fetch",
            "+refs/heads/main:refs/remotes/upstream/main")
        reasons, _ = incomplete_history(repo)
        assert any("single-branch clone" in r for r in reasons), reasons
        assert any("release/1.x" in r for r in reasons), reasons

    def test_a_remote_with_no_url_says_so(self, tmp_path):
        """A remote section whose URL was unset is not the same as no remote at all,
        and silence there reads as coverage nobody checked.
        """
        from deptrail.history import incomplete_history
        repo = self.fresh(tmp_path, "urlless")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        git(repo, "config", "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*")
        reasons, notes = incomplete_history(repo)
        assert reasons == []
        assert any("no URL to ask" in n for n in notes), notes

    def test_every_remote_is_asked_because_none_of_them_records_the_source(
            self, tmp_path):
        """Picking one remote produced three separate false all-clears in turn --
        the name `origin` assumed, then `origin` preferred over the remote a
        `-o upstream` clone came from, then the branch's own upstream, which names
        where a branch pulls from and not where the clone came from. Nothing records
        the source, so every remote is asked and a branch none of them accounts for
        is one the walk cannot testify about.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "everyremote")
        empty = tmp_path / "empty.git"
        git(tmp_path, "init", "-q", "--bare", str(empty))
        repo = self.fresh(tmp_path, "everyremote-clone")
        # The remote holding the unfetched branch is not called origin, and is not
        # the one the current branch tracks.
        git(repo, "remote", "add", "origin", str(empty))
        git(repo, "remote", "add", "upstream", str(origin))
        git(repo, "fetch", "-q", "upstream", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        git(repo, "config", "branch.main.remote", "origin")
        reasons, _ = incomplete_history(repo)
        assert any("upstream/release/1.x" in r for r in reasons), reasons

    def test_a_remote_defined_the_old_way_is_still_a_remote(self, tmp_path):
        """`$GIT_DIR/remotes/<name>` predates the config sections, git still fetches
        through it, and `git remote` does not list it — so a clone using one looked
        like a clone with no remote at all, which costs nothing and says nothing.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "legacy")
        repo = self.fresh(tmp_path, "legacy-clone")
        remotes = repo / ".git" / "remotes"
        remotes.mkdir(parents=True)
        (remotes / "origin").write_text(
            f"URL: {origin}\nPull: refs/heads/main:refs/remotes/origin/main\n")
        git(repo, "fetch", "-q", "origin", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        reasons, _ = incomplete_history(repo)
        assert any("release/1.x" in r for r in reasons), reasons

    def test_a_partial_wildcard_refspec_is_not_every_head(self, tmp_path):
        """`refs/heads/release/*` fetches nothing outside `release/`, and reading any
        `*` as completeness cleared every branch beside it. A negative refspec takes
        branches back out of whatever the positive ones brought, so a clone carrying
        one has not fetched every head either.
        """
        from deptrail.history import _fetches_every_head
        assert _fetches_every_head("+refs/heads/*:refs/remotes/origin/*")
        assert not _fetches_every_head(
            "+refs/heads/release/*:refs/remotes/origin/release/*")
        assert not _fetches_every_head(
            "+refs/heads/*:refs/remotes/origin/*\n^refs/heads/secret")

    def test_a_remote_named_the_older_old_way_is_still_a_remote(self, tmp_path):
        """`$GIT_DIR/branches/<name>` is the second spelling that predates the config
        sections. git still fetches through it and `git remote` does not list it, so
        a clone using one looked like a clone with no remote at all.
        """
        from deptrail.history import _remotes
        repo = self.fresh(tmp_path, "branches-shorthand")
        shorthand = repo / ".git" / "branches"
        shorthand.mkdir(parents=True)
        (shorthand / "legacy").write_text(str(tmp_path / "somewhere.git") + "\n")
        assert "legacy" in _remotes(repo)

    def test_an_inherited_git_dir_cannot_answer_for_another_repository(
            self, tmp_path, monkeypatch):
        """`GIT_DIR` outranks `-C`, and the last git call here that had not been told
        so was the one that asks whether a path existed at a commit — which decides
        whether a lockfile this tool cannot read was there during the window. Under
        an inherited `GIT_DIR` it answered about a different repository, the tree
        stopped being a witness, and a repository that could not be judged was
        cleared instead.
        """
        from deptrail.history import scan_repo
        repo = self.fresh(tmp_path, "foreign-tree")
        self.write(repo, "package.json", '{"name": "x"}\n',
                   "2025-11-25T10:00:00+00:00")
        self.write(repo, "bun.lockb", "lockfile\n", "2025-11-25T10:30:00+00:00")
        elsewhere = self.fresh(tmp_path, "elsewhere")
        self.write(elsewhere, "README.md", "nothing here\n",
                   "2025-11-25T10:00:00+00:00")
        monkeypatch.setenv("GIT_DIR", str(elsewhere / ".git"))
        assert scan_repo(repo, WINDOW).verdict is Verdict.INDETERMINATE

    def test_a_credential_helper_named_by_the_environment_is_not_asked(
            self, tmp_path, monkeypatch):
        """`GIT_ASKPASS` is exported by VS Code, GitHub Desktop and `gh auth
        setup-git`, and it hands a stored password to whatever host git is talking
        to — which here is a host the scanned repository named.
        """
        import http.server
        import threading
        from deptrail.history import _remote_heads

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # The host asks for credentials, which is what sends git looking
                # for one; without it the connection fails first and askpass is
                # never reached.
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="x"')
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        witness = tmp_path / "asked"
        askpass = tmp_path / "askpass.sh"
        askpass.write_text(f"#!/bin/sh\ntouch {witness}\necho secret\n")
        askpass.chmod(0o755)
        monkeypatch.setenv("GIT_ASKPASS", str(askpass))
        monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "http")
        repo = self.fresh(tmp_path, "askpass-clone")
        git(repo, "remote", "add", "origin",
            f"http://127.0.0.1:{server.server_address[1]}/x.git")
        try:
            assert _remote_heads(repo, "origin") is None
            assert not witness.exists()
        finally:
            server.shutdown()

    def test_a_token_is_written_for_a_named_address_and_never_asked_for(
            self, tmp_path, monkeypatch):
        """The probe holds one credential and only one: a token written into its own
        config for an address the operator named. Letting a credential *helper*
        answer instead meant that a stale token drew a 401, git asked the helper,
        git then ran `credential erase`, and a read-only scan deleted the operator's
        saved GitHub login — from an ordinary run, and from `pytest` with every test
        green.
        """
        from deptrail import history
        origin = self.origin_with_two_branches(tmp_path, "written-token")
        repo = self.fresh(tmp_path, "written-token-clone")
        monkeypatch.setattr(history, "_github_authorization",
                            lambda url: "Authorization: Basic PRETEND")
        seen: list[str] = []
        helpers: list[list[str]] = []
        real = history.subprocess.Popen

        class Spy(real):
            def __init__(self, args, **kwargs):
                if isinstance(args, list) and "ls-remote" in args:
                    probe = args[args.index("-C") + 1]
                    seen.append((Path(probe) / ".git" / "config").read_text())
                    # Asked of git, in the probe's own environment, rather than
                    # read off the file: `"helper =" in text` is satisfied by
                    # `helper = /bin/false` too, so it named a behaviour and
                    # checked a substring.
                    asked = subprocess.run(
                        ["git", "-C", probe, "config", "--get-all",
                         "credential.helper"],
                        env=kwargs.get("env"), capture_output=True, text=True)
                    helpers.append(asked.stdout.splitlines())
                super().__init__(args, **kwargs)

        monkeypatch.setattr(history.subprocess, "Popen", Spy)
        heads = history._remote_heads(repo, "origin", trusted_url=str(origin))
        assert heads is not None and "release/1.x" in heads, heads
        assert "Authorization: Basic PRETEND" in seen[0], seen[0]
        # No helper may run: that is the path that erases. The list git reports is
        # the reset entry and nothing after it — `[]` would mean the reset was
        # dropped, and anything non-empty is a helper that can be asked.
        assert helpers[0] == [""], helpers[0]

    def test_no_token_is_written_when_the_caller_says_not_to_authenticate(
            self, tmp_path, monkeypatch):
        """`--no-ci` withholds the token. It does not withhold the check: doing that
        made the same clone exit 2 without the flag and 0 with it, with nothing in
        the report to say why.
        """
        from deptrail import history
        origin = self.origin_with_two_branches(tmp_path, "unauth")
        repo = self.fresh(tmp_path, "unauth-clone")
        monkeypatch.setattr(history, "_github_authorization",
                            lambda url: "Authorization: Basic PRETEND")
        seen: list[str] = []
        real = history.subprocess.Popen

        class Spy(real):
            def __init__(self, args, **kwargs):
                if isinstance(args, list) and "ls-remote" in args:
                    probe = args[args.index("-C") + 1]
                    seen.append((Path(probe) / ".git" / "config").read_text())
                super().__init__(args, **kwargs)

        monkeypatch.setattr(history.subprocess, "Popen", Spy)
        heads = history._remote_heads(repo, "origin", trusted_url=str(origin),
                                      authenticate=False)
        assert heads is not None, "the named address is still asked"
        assert "PRETEND" not in seen[0], seen[0]

    @pytest.fixture
    def no_gh(self, monkeypatch):
        """`gh` never really runs, and no ambient host speaks for a token.

        With the operator's own login answering, every assertion about the
        *environment* is satisfied by the fallback instead — measured, deleting the
        `GITHUB_TOKEN` lookup altogether left these tests passing and the whole
        suite green. It also keeps a real token out of an assertion message.

        Yields the list of `(argv, env)` the fallback was called with.
        """
        from deptrail import history
        monkeypatch.delenv("GH_HOST", raising=False)
        monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        called: list[tuple[list[str], dict]] = []
        monkeypatch.setattr(
            history.subprocess, "run",
            lambda *a, **k: (called.append((a[0], k.get("env") or {}))
                             or subprocess.CompletedProcess(a, 1, "", "")))
        return called

    def test_a_token_is_only_for_github_and_only_over_https(self, monkeypatch,
                                                            no_gh):
        """The header is built for the operator's own forge and for nothing else,
        under both names the environment spells a token.
        """
        from deptrail import history
        monkeypatch.setenv("GH_TOKEN", "ghs_TESTTOKEN")
        assert history._github_authorization("https://github.com/o/r.git")
        assert history._github_authorization("https://evil.example/o/r.git") is None
        # Plain http would put the header on the wire before a redirect could
        # upgrade it.
        assert history._github_authorization("http://github.com/o/r.git") is None
        # Read under its second name too: the reason this code prints tells
        # operators to set GITHUB_TOKEN.
        monkeypatch.delenv("GH_TOKEN")
        monkeypatch.setenv("GITHUB_TOKEN", "ghs_SECONDNAME")
        assert history._github_authorization("https://github.com/o/r.git")

    def test_an_ambient_token_belongs_to_the_server_that_minted_it(
            self, monkeypatch, no_gh):
        """`GH_HOST` picks `gh`'s default *target*; it does not re-home a token, and
        testing it refused a github.com PAT for github.com — an operator who exported
        it for their enterprise had a complete scan of a private github.com
        repository turned from 0 into 2. `GITHUB_SERVER_URL` is the one that does say
        where a token lives: Actions sets it to the instance that minted the run's
        token, so on a GHES runner `GH_TOKEN: ${{ github.token }}` — which this
        project's own action.yml writes — is that instance's. `gh` never consults it,
        so pinning `--hostname` cannot catch this one.
        """
        from deptrail import history
        # Both, or asserting that the fallback was not handed one of them is
        # satisfied by its never having been set: measured, dropping the
        # `GITHUB_TOKEN` pop from that environment left this test passing.
        monkeypatch.setenv("GH_TOKEN", "ghs_TESTTOKEN")
        monkeypatch.setenv("GITHUB_TOKEN", "ghs_SECONDNAME")
        for value in ("ghe.example.com", "github.com", "user@github.com", ""):
            monkeypatch.setenv("GH_HOST", value)
            assert history._github_authorization(
                "https://github.com/o/r.git"), f"GH_HOST={value!r}"
        monkeypatch.delenv("GH_HOST")
        for value in ("https://ghe.example.com", "https://ghe.example.com/",
                      # No scheme is how an operator would type it, and reading the
                      # host as `partition("://")[2]` made it the empty string, took
                      # that for "nobody named a host", and sent the enterprise token.
                      "ghe.example.com", "ghe.example.com/x",
                      "https:/ghe.example.com", "://", "not a url"):
            monkeypatch.setenv("GITHUB_SERVER_URL", value)
            no_gh.clear()
            assert history._github_authorization(
                "https://github.com/o/r.git") is None, f"GITHUB_SERVER_URL={value!r}"
            # Refusing the variable is not enough while the fallback can read it
            # back: measured, `GH_TOKEN=X gh auth token --hostname github.com` prints
            # X, so `gh` handed back the exact credential refused here.
            assert no_gh, f"the fallback was never reached for {value!r}"
            _argv, env = no_gh[0]
            assert "GH_TOKEN" not in env and "GITHUB_TOKEN" not in env, sorted(env)
        # And the shipped Action's own environment still gets a token. Every earlier
        # test deleted these rather than setting them to a github.com value, so a
        # parse that forgot the scheme — withholding on every plain Actions run, and
        # so blocking every private repository at exit 2 — left the suite green.
        for value in ("https://github.com", "https://github.com/", "https://GITHUB.COM/",
                      "https://github.com/o/r", "https://github.com:443", "github.com",
                      "https://user@github.com", ""):
            monkeypatch.setenv("GITHUB_SERVER_URL", value)
            assert history._github_authorization(
                "https://github.com/o/r.git"), f"GITHUB_SERVER_URL={value!r}"

    def test_the_stored_login_is_asked_for_the_host_it_will_be_sent_to(self, no_gh):
        """`gh auth token` answers for whatever `GH_HOST` names, so an operator
        logged in to a GitHub Enterprise instance had that instance's stored
        credential handed to github.com.
        """
        from deptrail import history
        assert history._github_authorization("https://github.com/o/r.git") is None
        assert no_gh and no_gh[0][0] == ["gh", "auth", "token",
                                         "--hostname", "github.com"], no_gh

    def test_the_token_is_not_attached_to_an_address_the_repository_chose(
            self, tmp_path, monkeypatch):
        """Keyed on the URL alone, a scan with `GH_TOKEN` in its environment — every
        Action, `--no-ci` among them — attached the token to a github.com URL read
        from the checkout's own config, which is an address the repository chose.
        """
        from deptrail import history
        monkeypatch.setenv("GH_TOKEN", "ghs_LEAKME")
        # No `GIT_ALLOW_PROTOCOL` of its own: the suite allows `file` and nothing
        # else, so the transport is refused before any connection is made. What is
        # under test is the config this code writes, which is written first and
        # read by the spy below — overriding the guarantee to `https` sent this
        # bogus credential to the real github.com on every run.
        # The environment this runs in decides which token is built, and the
        # assertion below only asks whether *a* header exists. On a machine with
        # `GITHUB_SERVER_URL` naming an enterprise it failed; on one with `gh`
        # logged in it passed carrying a credential this test never set, which is
        # worse. Both variables are pinned, and the header is compared to the exact
        # value this test provided.
        monkeypatch.delenv("GH_HOST", raising=False)
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        expected = base64.b64encode(b"x-access-token:ghs_LEAKME").decode()
        repo = self.fresh(tmp_path, "tokenscope")
        git(repo, "remote", "add", "origin", "https://github.com/o/r.git")
        seen: list[str] = []
        real = history.subprocess.Popen

        class Spy(real):
            def __init__(self, args, **kwargs):
                if isinstance(args, list) and "ls-remote" in args:
                    probe = args[args.index("-C") + 1]
                    seen.append((Path(probe) / ".git" / "config").read_text())
                super().__init__(args, **kwargs)

        monkeypatch.setattr(history.subprocess, "Popen", Spy)
        history._remote_heads(repo, "origin")
        history._remote_heads(repo, "origin",
                              trusted_url="https://github.com/o/r.git")
        assert len(seen) == 2, seen
        assert "extraHeader" not in seen[0], seen[0]
        assert expected in seen[1], seen[1]

    @pytest.mark.parametrize("failure", [
        FileNotFoundError(2, "No such file or directory: 'gh'"),
        subprocess.TimeoutExpired(["gh"], 10),
    ])
    def test_a_missing_credential_helper_is_a_missing_credential(
            self, tmp_path, monkeypatch, failure):
        """`gh` not being installed raised out of `_github_authorization`, out of
        `_remote_heads` *before* `ls-remote` was ever built, and `_ref_coverage`
        read that as the named address falling silent — so `pip install deptrail` on
        a box without `gh` reported a public, complete clone as incomplete and told
        the operator to go and set a token. A `gh` that hangs arrives by
        `TimeoutExpired`, which the query's own timeout makes reachable.
        """
        from deptrail import history
        monkeypatch.delenv("GH_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        origin = self.origin_with_two_branches(tmp_path, "nogh")
        repo = tmp_path / "nogh-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        real = history.subprocess.run

        def refuse(args, *rest, **kwargs):
            if isinstance(args, list) and args and args[0] == "gh":
                raise failure
            return real(args, *rest, **kwargs)

        monkeypatch.setattr(history.subprocess, "run", refuse)
        # A trusted URL that reaches the `gh` lookup at all has to be an https
        # github.com one — that is the only shape the header is built for, and the
        # only shape the CLI produces.
        header = history._github_authorization("https://github.com/o/r.git")
        assert header is None, header
        # And the query still happens: the clone is complete, so there is no gap.
        reason, _ = history._ref_coverage(repo, None, str(origin), True)
        assert reason is None, reason

    def test_a_named_address_is_still_checked_like_any_other_url(
            self, tmp_path, monkeypatch):
        """Trusted means the *address* is the operator's, not that the string is
        safe. Taken as given it skipped the checks a remote's URL gets: a value
        beginning with `-` reaches git as an option, a control character breaks out
        of the config line it is written on, and an embedded credential is handed
        whole to git's transport helper, where `ps` and `GIT_TRACE` see it.
        """
        from deptrail import history
        repo = self.fresh(tmp_path, "checked")
        seen: list[str] = []
        real = history.subprocess.Popen

        class Spy(real):
            def __init__(self, args, **kwargs):
                if isinstance(args, list) and "ls-remote" in args:
                    probe = args[args.index("-C") + 1]
                    seen.append((Path(probe) / ".git" / "config").read_text())
                super().__init__(args, **kwargs)

        monkeypatch.setattr(history.subprocess, "Popen", Spy)
        for hostile in ("--upload-pack=touch pwned",
                        'https://github.com/o/r.git"\n[core]\n\tpager = touch pwned'):
            assert history._remote_heads(repo, "origin", trusted_url=hostile) is None
        assert not seen, seen
        history._remote_heads(
            repo, "origin", trusted_url="https://user:PAT@github.com/o/r.git")
        assert seen and "PAT" not in seen[0], seen

    def test_the_probe_does_not_follow_a_redirect_to_another_host(
            self, tmp_path, monkeypatch):
        """Git's default `followRedirects = initial` rebases the remote URL on the
        redirect target, and protocol v2's second request then goes to the new host
        as a fresh request — measured, carrying the header written for the address
        the operator named. The branch list came back from the host that answered
        the redirect rather than the one that was asked.
        """
        from deptrail import history
        repo = self.fresh(tmp_path, "redirected")
        git(repo, "remote", "add", "origin", "https://example.invalid/x.git")
        seen: list[str] = []
        real = history.subprocess.Popen

        class Spy(real):
            def __init__(self, args, **kwargs):
                if isinstance(args, list) and "ls-remote" in args:
                    probe = args[args.index("-C") + 1]
                    seen.append((Path(probe) / ".git" / "config").read_text())
                super().__init__(args, **kwargs)

        monkeypatch.setattr(history.subprocess, "Popen", Spy)
        history._remote_heads(repo, "origin")
        assert seen, "the probe never ran"
        assert "followRedirects = false" in seen[0], seen[0]

    def test_verification_cannot_be_turned_off_from_the_environment(
            self, tmp_path, monkeypatch):
        """The probe carries a credential now — one the operator never put in the
        environment, since `gh auth token` supplies it — while the setting that
        decides who may receive it was still whatever the environment said.
        `GIT_SSL_NO_VERIFY` cannot be answered from the config this probe writes:
        measured against a self-signed endpoint, an explicit `http.sslVerify = true`
        in the probe's own file loses to it.
        """
        from deptrail import history
        monkeypatch.setenv("GIT_SSL_NO_VERIFY", "1")
        # Kept, deliberately: an operator behind a TLS-intercepting proxy has no
        # other way to make the query work, and naming a CA still verifies.
        monkeypatch.setenv("GIT_SSL_CAINFO", "/corp/ca.pem")
        repo = self.fresh(tmp_path, "verify")
        git(repo, "remote", "add", "origin", "https://example.invalid/x.git")
        seen: list[dict] = []
        real = history.subprocess.Popen

        class Spy(real):
            def __init__(self, args, **kwargs):
                if isinstance(args, list) and "ls-remote" in args:
                    seen.append(kwargs.get("env") or {})
                super().__init__(args, **kwargs)

        monkeypatch.setattr(history.subprocess, "Popen", Spy)
        history._remote_heads(repo, "origin")
        assert seen, "the probe never ran"
        assert "GIT_SSL_NO_VERIFY" not in seen[0], sorted(seen[0])
        assert seen[0].get("GIT_SSL_CAINFO") == "/corp/ca.pem", sorted(seen[0])

    def test_the_cache_remembers_which_address_was_asked(self, tmp_path):
        """The answer stopped being a property of the checkout alone when the
        address the operator named became one of the sources. Keyed on the path, one
        cache reused across both handed back the first call's non-blocking caveat in
        place of the second call's blocking reason.
        """
        from deptrail.history import _ref_coverage
        repo = self.fresh(tmp_path, "cached")
        gone = tmp_path / "not-there.git"
        git(repo, "remote", "add", "origin", str(gone))
        cache: dict = {}
        first, _ = _ref_coverage(repo, cache, None, True)
        assert first is None, first
        second, _ = _ref_coverage(repo, cache, str(gone), True)
        assert second is not None and "produced no branch list" in second, second

    def test_a_named_address_with_no_branches_blocks_like_one_that_was_silent(
            self, tmp_path):
        """`None` meant "could not be asked" and a non-empty dict meant "answered",
        and an empty advertisement was neither — so a named address that produced one
        went into no list at all, skipped the blocking path, and the clone came back
        clean with an unwalkable branch on its own origin.
        """
        from deptrail.history import _ref_coverage
        empty = tmp_path / "no-branches.git"
        git(tmp_path, "init", "-q", "--bare", str(empty))
        origin = self.origin_with_two_branches(tmp_path, "branchless")
        repo = self.fresh(tmp_path, "branchless-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        # The clone is missing `release/1.x`, and neither source can say so: its own
        # origin is out of reach and the named address has nothing to advertise.
        git(repo, "remote", "set-url", "origin", str(tmp_path / "moved-away.git"))
        reason, _ = _ref_coverage(repo, None, str(empty), True)
        assert reason is not None, reason
        assert "produced no branch list" in reason, reason

    def test_a_source_that_advertises_nothing_has_not_answered(self, tmp_path):
        """`_remote_heads` returns an empty dict, not None, for a remote serving no
        refs, so it counted as an answer and the note named it as what a clean
        result rested on. It had said nothing.
        """
        from deptrail.history import _ref_coverage
        empty = tmp_path / "empty-origin.git"
        git(tmp_path, "init", "-q", "--bare", str(empty))
        repo = self.fresh(tmp_path, "restson")
        git(repo, "remote", "add", "hollow", str(empty))
        git(repo, "remote", "add", "unreachable", str(tmp_path / "not-there.git"))
        reason, note = _ref_coverage(repo, None)
        assert reason is None, reason
        assert note is not None and "unreachable" in note, note
        assert "rests on" not in note, note

    def test_a_remote_cannot_take_the_name_the_report_uses_for_the_operator(
            self, tmp_path):
        """A remote's name is a config section or a filename, so a clone can call one
        of its own remotes exactly what this code calls the operator's address. The
        report then said "not verified against the repository you named, and rests on
        the repository you named" and attributed that remote's gaps to the address
        the operator gave.
        """
        from deptrail.history import NAMED_ADDRESS, _ref_coverage
        origin = self.origin_with_two_branches(tmp_path, "impostor")
        repo = tmp_path / "impostor-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        # `git remote add` refuses the name; the legacy shorthand does not, and git
        # fetches through it either way.
        legacy = repo / ".git" / "remotes"
        legacy.mkdir(parents=True, exist_ok=True)
        (legacy / NAMED_ADDRESS).write_text(
            f"URL: {tmp_path / 'not-there.git'}\n")
        reason, note = _ref_coverage(repo, None, str(origin), True)
        assert reason is None, reason
        assert note is not None, note
        # The impostor is named as a remote, and what coverage rests on is the
        # address the operator actually gave.
        assert f'remote "{NAMED_ADDRESS}"' in note, note
        assert note.partition("rests on")[2].strip().startswith(NAMED_ADDRESS), note

    def test_a_named_address_nobody_could_ask_is_a_reason_and_not_a_note(
            self, tmp_path):
        """Withholding the token withheld the answer. On a private repository the
        unauthenticated query is refused, the clone's own remote is that same
        address and is refused too, every source falls silent — and the check that
        ran, found nothing to say, and cleared the clone. Measured end to end, the
        same clone with the poisoned pin on an unfetched branch exited 2 without
        `--no-ci` and 0 with it.
        """
        from deptrail.history import _ref_coverage
        repo = self.fresh(tmp_path, "unanswerable")
        gone = tmp_path / "no-such-repository.git"
        git(repo, "remote", "add", "origin", str(gone))
        reason, note = _ref_coverage(repo, None, str(gone), False)
        assert reason is not None and "produced no branch list" in reason, reason
        # Said once. It was the reason, so repeating it as an observation would
        # print the same sentence twice on every report.
        assert note is None, note
        # The clone's own remotes are not addresses the operator named, and
        # interpolating the whole silent list into that sentence said they were.
        # Counted, not just located: adding a second parenthetical that lists every
        # silent source leaves "could not be asked either" intact, so a test looking
        # only for that clause cannot tell the two sentences apart.
        assert "(origin produced none either)" in reason, reason
        assert reason.count("origin") == 1, reason
        # The token is the remedy for the case that is known to be about a token.
        assert "`--no-ci` withholds it" in reason, reason
        reachable, _ = _ref_coverage(repo, None, str(gone), True)
        # And not for the rest of them: a deleted repository, a mistyped slug or no
        # network all arrive here, and telling that operator to set a token
        # prescribes a fix for something that is not wrong.
        assert reachable is not None, reachable
        assert "`--no-ci` withholds it" not in reachable, reachable
        assert "It was unreachable" in reachable, reachable

    def test_another_remote_cannot_answer_for_the_address_the_operator_named(
            self, tmp_path):
        """The first fix let any answer stand in, and that is a hole the scanned
        repository can open by itself: it chooses which remotes it has, so a public
        fork, a stale mirror or a plain decoy — any address whose heads the clone
        already holds — turned the named repository's silence back into a note and
        cleared the clone.
        """
        from deptrail.history import _ref_coverage
        decoy = self.origin_with_two_branches(tmp_path, "decoy-remote")
        repo = tmp_path / "decoyed"
        git(tmp_path, "clone", "-q", str(decoy), str(repo))
        git(repo, "fetch", "-q", "origin", "release/1.x")
        # The decoy answers and holds nothing this clone is missing.
        assert _ref_coverage(repo, None)[0] is None
        # The address the operator named cannot be asked, and that is still a
        # reason: the decoy is not it.
        reason, _ = _ref_coverage(repo, None, str(tmp_path / "named-but-gone.git"),
                                  True)
        assert reason is not None and "produced no branch list" in reason, reason

    def test_silence_beside_an_answer_says_what_the_answer_covered(self, tmp_path):
        """"Coverage was not verified" is false on the shipped Action's ordinary
        shape: the named address answers in full while the checkout's own `origin`,
        whose credential lives in the config this probe refuses to read, cannot be
        asked at all. The unqualified sentence fired on exactly the runs where the
        feature was working.
        """
        from deptrail.history import _ref_coverage
        origin = self.origin_with_two_branches(tmp_path, "beside")
        repo = tmp_path / "beside-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        git(repo, "remote", "add", "unreachable", str(tmp_path / "not-here.git"))
        reason, note = _ref_coverage(repo, None, str(origin), True)
        assert reason is None, reason
        assert note is not None and "unreachable" in note, note
        # What it rests on has to be what answered. Naming the silent source there
        # instead is the same false sentence this note replaced, and asserting only
        # that "rests on" appears let that mutation through the whole suite.
        rests_on = note.partition("rests on")[2]
        assert "the repository you named" in rests_on, note
        assert "unreachable" not in rests_on, note

    def test_two_remotes_missing_the_same_name_at_different_tips_are_two_gaps(
            self, tmp_path):
        """A gap is a branch *at a tip*. Keyed on the name alone the second was
        dropped, and fetching the source that was named would have left the other
        unexamined.
        """
        from deptrail.history import _ref_coverage
        first = self.origin_with_two_branches(tmp_path, "twin-a")
        second = self.origin_with_two_branches(tmp_path, "twin-b")
        # The helper is deterministic, so the two origins would otherwise carry the
        # same commits under the same names — one gap, correctly counted once.
        elsewhere = tmp_path / "twin-b-work"
        git(elsewhere, "checkout", "-q", "release/1.x")
        self.write(elsewhere, "diverged.md", "not the same commit\n",
                   "2025-11-26T10:00:00+00:00")
        git(elsewhere, "push", "-q", "origin", "release/1.x")
        repo = self.fresh(tmp_path, "twin-clone")
        git(repo, "remote", "add", "one", str(first))
        git(repo, "remote", "add", "two", str(second))
        git(repo, "fetch", "-q", "one", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        reason, _ = _ref_coverage(repo, None)
        # Both origins carry a `release/1.x`, and they are different commits.
        assert reason and reason.count("release/1.x") == 2, reason

    def test_a_named_address_that_cannot_answer_does_not_silence_the_clone(
            self, tmp_path):
        """The address the operator named is asked as well as the clone's remotes,
        never instead of them. Replacing them looked reasonable — they named it, so
        it is the authority — and it put #27 back: with the named address silent,
        nothing else was asked and the same clone that exits 2 without a slug came
        back clean with one.
        """
        from deptrail.history import _ref_coverage
        origin = self.origin_with_two_branches(tmp_path, "fallback")
        repo = self.fresh(tmp_path, "fallback-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        reason, note = _ref_coverage(repo, None, "https://unreachable.invalid/x.git")
        assert reason and "release/1.x" in reason, (reason, note)
        # Both block, so the branches — the actionable half — stay the reason and
        # the silence is still said, once, beside them.
        assert note and "the address you named produced no branch list" in note, note

    def test_a_branch_both_sources_miss_is_reported_once(self, tmp_path):
        """The named address and a remote of the clone are usually the same
        repository, so the same branch comes back from both; two lines read as two
        gaps.
        """
        from deptrail.history import _ref_coverage
        origin = self.origin_with_two_branches(tmp_path, "onceonly")
        repo = self.fresh(tmp_path, "onceonly-clone")
        git(repo, "remote", "add", "origin", str(origin))
        git(repo, "fetch", "-q", "origin", "main")
        git(repo, "checkout", "-qb", "main", "FETCH_HEAD")
        reason, _ = _ref_coverage(repo, None, str(origin))
        assert reason and reason.count("release/1.x") == 1, reason
        assert reason.startswith("1 branch(es)"), reason

    def test_config_injected_by_the_environment_is_not_carried(self, tmp_path,
                                                               monkeypatch):
        """`GIT_CONFIG_COUNT` and its numbered keys are settings that arrive without
        a file, so disabling the global and system files and pointing `HOME` at an
        empty directory does not touch them — an inherited `http.extraHeader` still
        reached whatever address the scanned repository named.
        """
        import http.server
        import threading
        from deptrail.history import _remote_heads

        seen: list[str | None] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "http.extraHeader")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "Authorization: Bearer INJECTED")
        monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "http")
        repo = self.fresh(tmp_path, "injected")
        git(repo, "remote", "add", "origin",
            f"http://127.0.0.1:{server.server_address[1]}/x.git")
        try:
            assert _remote_heads(repo, "origin") is None
            assert seen, "the probe never reached the server"
            assert seen[0] is None, seen
        finally:
            server.shutdown()

    def test_config_git_itself_exports_is_not_carried_either(self, tmp_path,
                                                             monkeypatch):
        """`GIT_CONFIG_PARAMETERS` is the same channel as `GIT_CONFIG_COUNT` under a
        second name, and the one more likely to be inherited: git writes it for every
        child whenever the parent ran as `git -c key=value`, so a scan launched from
        an alias, a hook or `git rebase --exec` carries it. Measured, it survived the
        blanked `HOME` and the devnull config files, and it is command scope, so it
        outranks the file the probe writes for itself.
        """
        import http.server
        import threading
        from deptrail.history import _remote_heads

        seen: list[str | None] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        monkeypatch.setenv("GIT_CONFIG_PARAMETERS",
                           "'http.extraHeader=Authorization: Bearer INJECTED'")
        monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "http")
        repo = self.fresh(tmp_path, "exported")
        git(repo, "remote", "add", "origin",
            f"http://127.0.0.1:{server.server_address[1]}/x.git")
        try:
            assert _remote_heads(repo, "origin") is None
            assert seen, "the probe never reached the server"
            assert seen[0] is None, seen
        finally:
            server.shutdown()

    def test_a_tags_refspec_does_not_make_a_narrow_clone_look_wide(self, tmp_path):
        """The refspec is one per line, and each line is judged on its own: testing
        the whole blob for a `*` meant that adding the documented tags refspec to a
        single-branch clone — one line, no other change — silenced the reason.
        """
        from deptrail.history import incomplete_history
        origin = self.origin_with_two_branches(tmp_path, "tagspec")
        repo = tmp_path / "tagspec-clone"
        git(tmp_path, "clone", "-q", "--single-branch", "--branch", "main",
            str(origin), str(repo))
        git(repo, "config", "--add", "remote.origin.fetch",
            "+refs/tags/*:refs/tags/*")
        reasons, _ = incomplete_history(repo)
        assert any("single-branch clone" in r for r in reasons), reasons

    def test_a_network_url_is_not_resolved_against_the_checkout(self, tmp_path):
        """`repo / url` turned `https://host/repo.git` into the candidate path
        `<checkout>/https:/host/repo.git`. A compromised checkout can ship a bare
        repository there advertising exactly the branches already held, and the
        probe would have asked the decoy it was handed.
        """
        from deptrail.history import _remote_url
        repo = self.fresh(tmp_path, "decoy-clone")
        if os.name == "nt":
            # Windows has no name a scheme can be written as, so the path the
            # naive join produces cannot be planted at all — and `exists()` on
            # it answers False rather than raising. The decoy is unavailable to
            # an attacker there; what is left to hold is the return value.
            assert not (repo / "https:" / "host" / "repo.git").exists()
        else:
            origin = self.origin_with_two_branches(tmp_path, "decoy")
            decoy = repo / "https:/host"
            decoy.mkdir(parents=True)
            git(tmp_path, "clone", "-q", "--bare", str(origin),
                str(decoy / "repo.git"))
        git(repo, "remote", "add", "origin", "https://host/repo.git")
        assert _remote_url(repo, "origin") == "https://host/repo.git"

    def test_an_ssh_username_is_kept_because_it_is_not_a_credential(self, tmp_path):
        """`ssh://git@github.com/...` needs its `git`. Dropping it probed as whatever
        OS user the responder happens to be, so a reachable remote came back
        unreachable and its unfetched branches became a caveat instead of a reason.
        """
        from deptrail.history import _remote_url
        repo = self.fresh(tmp_path, "sshuser")
        git(repo, "remote", "add", "origin", "ssh://git@github.com/o/r.git")
        assert _remote_url(repo, "origin") == "ssh://git@github.com/o/r.git"

    def test_an_ambient_token_is_not_sent_to_the_remote_the_clone_names(
            self, tmp_path, monkeypatch):
        """The URL comes from a repository this code treats as hostile, and an
        unscoped `http.extraHeader` in the operator's own global config is sent to
        whatever host that URL names — measured, a bearer token reaching a server
        the scanned checkout chose.
        """
        import http.server
        import threading
        from deptrail.history import _remote_heads

        seen: list[str | None] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        home = tmp_path / "home"
        home.mkdir()
        (home / ".gitconfig").write_text(
            "[http]\n\textraHeader = Authorization: Bearer LEAKME\n")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "http")
        repo = self.fresh(tmp_path, "ambient")
        git(repo, "remote", "add", "origin",
            f"http://127.0.0.1:{server.server_address[1]}/x.git")
        try:
            assert _remote_heads(repo, "origin") is None
            assert seen, "the probe never reached the server"
            assert seen[0] is None, seen
        finally:
            server.shutdown()

    def test_a_rewritten_remote_is_asked_where_the_clone_actually_fetched(
            self, tmp_path):
        """`url.<base>.insteadOf` sends git somewhere other than the URL written in
        the config. Probing the literal value asked a repository this clone never
        fetched from, and its answer cleared branches nobody had.
        """
        from deptrail.history import _remote_heads
        origin = self.origin_with_two_branches(tmp_path, "rewritten")
        decoy = tmp_path / "decoy.git"
        git(tmp_path, "init", "-q", "--bare", str(decoy))
        repo = self.fresh(tmp_path, "rewritten-clone")
        git(repo, "config", f"url.{origin}.insteadOf", str(decoy))
        git(repo, "remote", "add", "origin", str(decoy))
        heads = _remote_heads(repo, "origin")
        assert heads is not None and "release/1.x" in heads, heads

    def test_a_ref_advertised_with_a_null_id_is_not_a_branch(self, tmp_path,
                                                             monkeypatch):
        """A ref whose name git will not accept is advertised with an all-zero id.
        Kept, the peeled rule overwrote a real branch's tip with it, and a branch
        this clone holds was reported as one it cannot walk.
        """
        from deptrail import history
        origin = self.origin_with_two_branches(tmp_path, "nullid")
        repo = tmp_path / "nullid-clone"
        git(tmp_path, "clone", "-q", str(origin), str(repo))
        real = history.subprocess.run

        def with_a_null_line(args, **kwargs):
            done = real(args, **kwargs)
            sink = kwargs.get("stdout")
            if (isinstance(args, list) and "ls-remote" in args
                    and done.returncode == 0 and hasattr(sink, "write")):
                # The advertisement is written to a file, so the extra lines go
                # there too rather than onto a captured string.
                sink.write(("0" * 40 + "\trefs/heads/release/1.x^{}\n"
                            + "0" * 40 + "\trefs/heads/broken\tname\n").encode())
            return done

        monkeypatch.setattr(history.subprocess, "run", with_a_null_line)
        heads = history._remote_heads(repo, "origin")
        assert history._heads_not_here(repo, heads) == [], heads

    def test_an_unreachable_remote_is_an_observation_and_not_a_reason(self, tmp_path):
        """A remote that cannot be reached leaves coverage unverified, which is worth
        saying and is not evidence of anything: refusing every offline scan its
        all-clear would cry wolf at complete clones, so the exit code is unchanged
        and the report carries the note.
        """
        from deptrail.history import incomplete_history
        repo = self.fresh(tmp_path, "unreachable")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        git(repo, "remote", "add", "origin", str(tmp_path / "gone-for-good.git"))
        reasons, notes = incomplete_history(repo)
        assert reasons == []
        assert any("ref coverage was not verified" in n for n in notes), notes
        assert scan_repo(repo, WINDOW).verdict is Verdict.CLEAN

    def test_a_full_clone_is_not_called_truncated(self, tmp_path):
        # The control: a wildcard refspec and no promisor must stay clean, or the
        # checks above would just be a way of never clearing anything.
        from deptrail.history import incomplete_history
        repo = self.fresh(tmp_path, "complete")
        self.write(repo, "package-lock.json", lock_json("5.6.0"),
                   "2025-11-25T10:00:00+00:00")
        git(repo, "config", "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*")
        # Reasons only: this fixture names a remote it never gave a URL, which is
        # its own observation now — what it pins is that a wildcard refspec and no
        # promisor cost the repository nothing.
        assert incomplete_history(repo)[0] == []
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
        monkeypatch.setitem(history.PARSED_LOCKFILES, "package-lock.json", parse)

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
        monkeypatch.setitem(history.PARSED_LOCKFILES, "package-lock.json", parse)
        repo = make_repo(tmp_path, "two-chalks", [("2025-11-25T12:00:00+00:00", "5.6.1")])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].chain == ("express", "debug", "chalk")
