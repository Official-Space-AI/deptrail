"""Walk the git history of a repo's lockfiles and judge exposure to an advisory.

Judgment model (shaped by adversarial review — see PR #8):

- **Graph order, never date order.** Commits are walked in the order git gives
  them along each ref's first-parent chain; commit dates are used only to
  compare against the attack window, never to order history. Date-sorting
  history lets a single skewed clock silently flip a verdict.
- **Conservative dual dates.** Rebase rewrites committer dates wholesale, so an
  interval starts at min(author, committer) of the pinning commit and ends at
  max(author, committer) of the replacing commit. Wide intervals can over-report
  exposure; they cannot under-report it. Large author/committer divergence on an
  exposing commit is surfaced as a warning.
- **Every ref testifies.** Exposure on an unmerged branch is still exposure —
  a CI runner built that branch. Each branch head gets its own first-parent
  interval walk; commits reachable only through merge side-lines degrade to
  point evidence (`commit:` prefix) because their pin duration is unknowable.
- **Unreadable evidence is never silence.** Snapshot read failures, parse
  failures, shallow clones, and discovered-but-unwalkable paths all become
  warnings, and a repo with warnings and no exposures is INDETERMINATE, not
  CLEAN.

The attack window is inclusive on both ends; held intervals are half-open
``[since, until)``.
"""
from __future__ import annotations

import posixpath
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from .lockfile import LockfileModel, LockfileParseError, parse_lockfile

LOCKFILE_BASENAME = "package-lock.json"
DATE_DIVERGENCE_WARN = timedelta(hours=48)


class GitError(RuntimeError):
    """A git invocation failed for a reason other than 'path absent at commit'."""


class Verdict(str, Enum):
    EXPOSED = "EXPOSED"
    CLEAN = "CLEAN"
    INDETERMINATE = "INDETERMINATE"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise GitError(f"git {args[0]} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def _parse_iso(stamp: str) -> datetime:
    """Python 3.10's fromisoformat rejects the 'Z' suffix git may emit."""
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


@dataclass(frozen=True)
class Commit:
    sha: str
    author_time: datetime
    committer_time: datetime

    @property
    def early(self) -> datetime:
        return min(self.author_time, self.committer_time)

    @property
    def late(self) -> datetime:
        return max(self.author_time, self.committer_time)

    @property
    def dates_diverge(self) -> bool:
        return abs(self.author_time - self.committer_time) > DATE_DIVERGENCE_WARN


@dataclass(frozen=True)
class WindowQuery:
    """The minimal question an advisory asks: package, bad versions, attack window."""

    package: str
    malicious_versions: frozenset[str]
    window_start: datetime
    window_end: datetime

    def __post_init__(self) -> None:
        for dt in (self.window_start, self.window_end):
            if dt.tzinfo is None or dt.utcoffset() is None:
                raise ValueError("attack window datetimes must be timezone-aware")
        if self.window_start > self.window_end:
            raise ValueError("attack window start is after its end")


@dataclass(frozen=True)
class Exposure:
    """One piece of evidence that a lockfile pinned a compromised version.

    ``evidence`` is ``interval:<ref>`` for a first-parent interval on a ref, or
    ``commit:<sha>`` for point evidence from a merge side-line (duration unknown).
    """

    lockfile_path: str
    version: str
    since: datetime
    until: datetime | None  # None = still pinned at the tip of that ref
    commit: str
    chain: tuple[str, ...]
    evidence: str

    @property
    def still_pinned(self) -> bool:
        return self.evidence == "interval:HEAD" and self.until is None


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

    @property
    def verdict(self) -> Verdict:
        """CLEAN is only claimable when nothing was exposed AND nothing was unreadable."""
        if self.exposures:
            return Verdict.EXPOSED
        if self.warnings:
            return Verdict.INDETERMINATE
        return Verdict.CLEAN


def is_shallow(repo: Path) -> bool:
    return _git(repo, "rev-parse", "--is-shallow-repository").strip() == "true"


def lockfile_paths(repo: Path) -> list[str]:
    """Every path where a lockfile ever lived on any ref, exact basename only.

    ``-z`` output is unquoted, so paths with non-ASCII or special characters
    survive; the basename check rejects look-alikes such as
    ``sample-package-lock.json``.
    """
    out = _git(repo, "log", "--all", "--format=", "--name-only", "-z",
               "--", f"*{LOCKFILE_BASENAME}")
    names = {n for n in out.replace("\n", "\0").split("\0") if n}
    return sorted(n for n in names if posixpath.basename(n) == LOCKFILE_BASENAME)


def _refs(repo: Path) -> list[str]:
    """HEAD first, then every branch head with a distinct tip."""
    out = _git(repo, "for-each-ref", "--format=%(refname) %(objectname)",
               "refs/heads", "refs/remotes")
    refs, seen_tips = ["HEAD"], {_git(repo, "rev-parse", "HEAD").strip()}
    for line in out.splitlines():
        name, tip = line.rsplit(" ", 1)
        if name.endswith("/HEAD") or tip in seen_tips:
            continue
        seen_tips.add(tip)
        refs.append(name)
    return refs


def _log_commits(repo: Path, path: str, *, ref: str | None = None,
                 first_parent: bool = False, follow: bool = False,
                 all_refs: bool = False) -> list[Commit]:
    """Commits touching one path, oldest to newest in git's own graph order."""
    args = ["log", "--format=%H|%aI|%cI"]
    if first_parent:
        args.append("--first-parent")
    if follow:
        args.append("--follow")
    if all_refs:
        args.append("--all")
    if ref:
        args.append(ref)
    args += ["--", path]
    commits = []
    for line in _git(repo, *args).strip().splitlines():
        if not line:
            continue
        sha, author, committer = line.split("|")
        commits.append(Commit(sha, _parse_iso(author), _parse_iso(committer)))
    commits.reverse()
    return commits


def _read_snapshot(repo: Path, sha: str, path: str,
                   finding: RepoFinding) -> LockfileModel | None:
    """Lockfile content at one commit; absence is normal, unreadability warns."""
    try:
        text = _git(repo, "show", f"{sha}:{path}")
    except GitError as e:
        message = str(e)
        if "does not exist" in message or "exists on disk, but not in" in message:
            return None  # the commit genuinely lacks the file (e.g. it deleted it)
        finding.warnings.append(f"{path}@{sha[:8]}: snapshot unreadable ({message})")
        return None
    try:
        return parse_lockfile(text)
    except LockfileParseError as e:
        finding.warnings.append(f"{path}@{sha[:8]}: unreadable snapshot ({e})")
        return None


def _chain_for(model: LockfileModel, package: str, version: str) -> tuple[str, ...]:
    """Evidence chain for one concrete version: physical nesting when the
    instance is nested, name-level shortest chain otherwise."""
    instance = next(
        (p for p in model.packages if p.name == package and p.version == version), None
    )
    if instance and instance.path.count("node_modules/") > 1:
        segments = [s.strip("/") for s in instance.path.split("node_modules/") if s]
        return tuple(segments)
    return tuple(model.chain_to(package) or (package,))


def _scan_ref_chain(repo: Path, path: str, ref: str, chain: list[Commit],
                    query: WindowQuery, finding: RepoFinding,
                    walked: set[str], seen: set[tuple]) -> None:
    for i, commit in enumerate(chain):
        walked.add(commit.sha)
        nxt = chain[i + 1] if i + 1 < len(chain) else None
        if nxt and nxt.late < commit.early:
            finding.warnings.append(
                f"{path}@{ref}: non-monotonic commit dates around {commit.sha[:8]} "
                "(clock skew or rebase); interval bounds are conservative"
            )
        since, until = commit.early, (nxt.late if nxt else None)
        # Half-open [since, until) against the inclusive window; skip snapshots
        # whose interval cannot overlap before spawning a git show.
        if since > query.window_end or (until is not None and until <= query.window_start):
            continue
        model = _read_snapshot(repo, commit.sha, path, finding)
        if model is None:
            continue
        bad = model.versions_of(query.package) & query.malicious_versions
        if not bad:
            continue
        if commit.dates_diverge:
            finding.warnings.append(
                f"{path}@{commit.sha[:8]}: author/committer dates diverge by >48h "
                "(history likely rewritten); dates used conservatively"
            )
        for version in sorted(bad):
            key = (path, commit.sha, version)
            if key in seen:
                continue
            seen.add(key)
            finding.exposures.append(Exposure(
                lockfile_path=path, version=version, since=since, until=until,
                commit=commit.sha, chain=_chain_for(model, query.package, version),
                evidence=f"interval:{ref}",
            ))


def scan_repo(repo: Path, query: WindowQuery) -> RepoFinding:
    """Judge one repository across every ref; see the module docstring for the model."""
    finding = RepoFinding(repo=repo)
    try:
        if is_shallow(repo):
            finding.warnings.append(
                "shallow clone: history is truncated, absence of exposure is not evidence"
            )
        paths = lockfile_paths(repo)
        refs = _refs(repo)
    except GitError as e:
        finding.warnings.append(str(e))
        return finding

    for path in paths:
        finding.lockfiles_seen += 1
        walked: set[str] = set()
        seen: set[tuple] = set()
        any_history = False

        for ref in refs:
            try:
                chain = _log_commits(repo, path, ref=ref, first_parent=True,
                                     follow=(ref == "HEAD"))
            except GitError as e:
                finding.warnings.append(f"{path}@{ref}: {e}")
                continue
            if chain:
                any_history = True
                _scan_ref_chain(repo, path, ref, chain, query, finding, walked, seen)

        # Merge side-lines: reachable commits not on any first-parent chain.
        # Their pin duration is unknowable, so they carry point evidence only.
        try:
            side = [c for c in _log_commits(repo, path, all_refs=True)
                    if c.sha not in walked]
        except GitError as e:
            finding.warnings.append(f"{path}: side-line walk failed ({e})")
            side = []
        if side:
            any_history = True
        for commit in side:
            if commit.early > query.window_end or commit.late < query.window_start:
                continue
            model = _read_snapshot(repo, commit.sha, path, finding)
            if model is None:
                continue
            for version in sorted(model.versions_of(query.package) & query.malicious_versions):
                key = (path, commit.sha, version)
                if key in seen:
                    continue
                seen.add(key)
                finding.exposures.append(Exposure(
                    lockfile_path=path, version=version,
                    since=commit.early, until=commit.late, commit=commit.sha,
                    chain=_chain_for(model, query.package, version),
                    evidence=f"commit:{commit.sha[:8]}",
                ))

        if not any_history:
            finding.warnings.append(
                f"{path}: discovered in refs but no walkable history (evidence unreadable)"
            )
    return finding
