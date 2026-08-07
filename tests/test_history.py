"""Integration tests for the history walker against synthetic git repos.

Each test builds a real git repo with faked commit dates, mirroring how the
walker will meet the world: history is the only witness.
"""
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from deptrail.history import WindowQuery, lockfile_paths, scan_repo

WINDOW = WindowQuery(
    package="chalk",
    malicious_versions=frozenset({"5.6.1"}),
    window_start=datetime.fromisoformat("2025-11-24T00:00:00+00:00"),
    window_end=datetime.fromisoformat("2025-11-26T23:59:59+00:00"),
)


def git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date} if date else {}
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True, capture_output=True, env={**__import__("os").environ, **env},
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
        assert finding.exposed
        exp = finding.exposures[0]
        assert exp.version == "5.6.1"
        assert exp.chain == ["express", "debug", "chalk"]
        assert exp.until is not None and not exp.still_pinned

    def test_clean_when_version_skipped_over_window(self, tmp_path):
        repo = make_repo(tmp_path, "clean", [
            ("2025-11-10T11:00:00+00:00", "5.6.0"),
            ("2025-11-29T16:00:00+00:00", "5.6.2"),
        ])
        assert not scan_repo(repo, WINDOW).exposed

    def test_exposure_before_window_does_not_count(self, tmp_path):
        repo = make_repo(tmp_path, "early", [
            ("2025-11-01T10:00:00+00:00", "5.6.1"),
            ("2025-11-20T10:00:00+00:00", "5.6.2"),
        ])
        assert not scan_repo(repo, WINDOW).exposed

    def test_still_pinned_is_open_interval(self, tmp_path):
        repo = make_repo(tmp_path, "pinned", [
            ("2025-11-25T14:30:00+00:00", "5.6.1"),
        ])
        finding = scan_repo(repo, WINDOW)
        assert finding.exposed
        assert finding.exposures[0].still_pinned

    def test_no_lockfile_repo(self, tmp_path):
        repo = tmp_path / "none"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "README.md").write_text("hi")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init", date="2025-11-01T00:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert not finding.exposed and finding.lockfiles_seen == 0


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
        assert finding.exposed  # the exposure happened even though the file is gone at HEAD
        assert not finding.exposures[0].still_pinned

    def test_unreadable_snapshot_warns_instead_of_silent_skip(self, tmp_path):
        repo = tmp_path / "broken"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "package-lock.json").write_text("{ not json at all")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "bad", date="2025-11-25T12:00:00+00:00")
        finding = scan_repo(repo, WINDOW)
        assert finding.warnings and "unreadable" in finding.warnings[0]

    def test_lockfile_paths_includes_deleted(self, tmp_path):
        repo = make_repo(tmp_path, "paths", [("2025-11-01T00:00:00+00:00", "5.6.0")])
        assert lockfile_paths(repo) == ["package-lock.json"]


class TestWindowQueryValidation:
    def test_naive_datetime_rejected(self):
        with pytest.raises(ValueError):
            WindowQuery("x", frozenset({"1"}), datetime(2025, 1, 1), WINDOW.window_end)

    def test_inverted_window_rejected(self):
        with pytest.raises(ValueError):
            WindowQuery("x", frozenset({"1"}), WINDOW.window_end, WINDOW.window_start)
