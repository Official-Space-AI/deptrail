"""Walk the git history of a repo's lockfiles and judge exposure to an advisory.

Interval semantics: a version is considered "held" from the commit that pinned
it until the next commit that changed that lockfile ([since, until)); the last
known state is an open interval (until=None) — still pinned today. A commit
timestamp says when the pin changed, not when an install actually ran; that
distinction is the job of CI-run correlation (issue #4), which upgrades or
downgrades the evidence grade.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .lockfile import LockfileModel, LockfileParseError, parse_lockfile

LOCKFILE_NAME = "package-lock.json"


@dataclass(frozen=True)
class WindowQuery:
    """The minimal question an advisory asks: package, bad versions, attack window."""

    package: str
    malicious_versions: frozenset[str]
    window_start: datetime
    window_end: datetime

    def __post_init__(self) -> None:
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError("attack window datetimes must be timezone-aware")
        if self.window_start > self.window_end:
            raise ValueError("attack window start is after its end")


@dataclass(frozen=True)
class Exposure:
    """One interval in which a lockfile pinned a compromised version."""

    lockfile_path: str
    version: str
    since: datetime
    until: datetime | None  # None = still pinned at the last known commit
    commit: str
    chain: list[str]

    @property
    def still_pinned(self) -> bool:
        return self.until is None


@dataclass
class RepoFinding:
    """Everything the walker learned about one repository."""

    repo: Path
    exposures: list[Exposure] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lockfiles_seen: int = 0

    @property
    def exposed(self) -> bool:
        return bool(self.exposures)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return result.stdout


def lockfile_paths(repo: Path) -> list[str]:
    """Every path where a lockfile ever lived — including ones deleted before HEAD.

    Monorepos keep one lockfile per package, so this returns all of them.
    """
    out = _git(repo, "log", "--all", "--format=", "--name-only", "--", f"*{LOCKFILE_NAME}")
    return sorted({line for line in out.splitlines() if line.endswith(LOCKFILE_NAME)})


def lockfile_commits(repo: Path, path: str) -> list[tuple[datetime, str]]:
    """Commits that touched one lockfile, ascending by commit time (renames followed)."""
    out = _git(repo, "log", "--follow", "--format=%H|%cI", "--", path)
    hist = []
    for line in out.strip().splitlines():
        sha, iso = line.split("|")
        hist.append((datetime.fromisoformat(iso), sha))
    return sorted(hist)


def _snapshot(repo: Path, sha: str, path: str) -> LockfileModel | None:
    """Lockfile content at one commit; None if it did not exist there (e.g. the
    commit that deleted it)."""
    try:
        text = _git(repo, "show", f"{sha}:{path}")
    except subprocess.CalledProcessError:
        return None
    return parse_lockfile(text)


def scan_repo(repo: Path, query: WindowQuery) -> RepoFinding:
    """Judge one repository: walk every lockfile's history, collect exposure
    intervals that overlap the attack window.

    A snapshot that fails to parse becomes a warning, never a silent skip —
    a repo must not look clean because its evidence was unreadable.
    """
    finding = RepoFinding(repo=repo)
    for path in lockfile_paths(repo):
        finding.lockfiles_seen += 1
        history = lockfile_commits(repo, path)
        for i, (t, sha) in enumerate(history):
            try:
                model = _snapshot(repo, sha, path)
            except LockfileParseError as e:
                finding.warnings.append(f"{path}@{sha[:8]}: unreadable snapshot ({e})")
                continue
            if model is None:
                continue
            bad = model.versions_of(query.package) & query.malicious_versions
            if not bad:
                continue
            until = history[i + 1][0] if i + 1 < len(history) else None
            if t <= query.window_end and (until is None or until >= query.window_start):
                chain = model.chain_to(query.package) or [query.package]
                for version in sorted(bad):
                    finding.exposures.append(
                        Exposure(
                            lockfile_path=path,
                            version=version,
                            since=t,
                            until=until,
                            commit=sha,
                            chain=chain,
                        )
                    )
    return finding
