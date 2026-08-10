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
- **Every ref testifies, merges included.** Exposure on an unmerged branch is
  still exposure — a CI runner built that branch. Each ref is walked in
  topological order over *all* its ancestry, not just the first-parent line: in
  a repo that merges pull requests, the commit that pinned a version usually
  sits on a side line, and treating it as a momentary point once made a
  two-day exposure read as CLEAN (found by replaying real history, see
  `docs/experiments.md`). An interval therefore ends at the first *descendant*
  commit whose snapshot no longer pins a named version — established with
  `merge-base --is-ancestor`, so incomparable branches widen an interval rather
  than truncating it.
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
                 all_refs: bool = False) -> list[Commit]:
    """Commits touching one path, ancestors first, in git's topological order.

    Topological order (not date order) is what makes interval reasoning sound:
    a parent always precedes its descendants regardless of what the clocks said.
    """
    args = ["log", "--topo-order", "--format=%H|%aI|%cI"]
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


def _commit_graph(repo: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Child and parent edges of the whole commit graph, read in one pass.

    Ancestry is asked thousands of times while pairing intervals, so it is
    answered in process from one ``rev-list`` rather than by spawning
    ``merge-base`` per pair — the difference between seconds and not finishing
    on a real repository.
    """
    children: dict[str, list[str]] = {}
    parents: dict[str, list[str]] = {}
    for line in _git(repo, "rev-list", "--all", "--parents").splitlines():
        shas = line.split()
        parents[shas[0]] = shas[1:]
        for parent in shas[1:]:
            children.setdefault(parent, []).append(shas[0])
    return children, parents


def _descendants(children: dict[str, list[str]], sha: str) -> set[str]:
    """Every commit reachable forward from `sha`, itself excluded."""
    seen: set[str] = set()
    stack = list(children.get(sha, ()))
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(children.get(current, ()))
    return seen


ABSENT = "absent"          # the commit genuinely has no lockfile there
UNREADABLE = "unreadable"  # we could not tell what it pinned


def _read_snapshot(repo: Path, sha: str, path: str,
                   finding: RepoFinding) -> LockfileModel | str:
    """Lockfile content at one commit, or why it is missing.

    Absence and unreadability must stay distinguishable: a commit that deleted
    the lockfile ends an exposure interval, while one we failed to read ends
    nothing and warns — otherwise a broken snapshot would silently close an
    interval and hide the exposure that followed it.
    """
    try:
        text = _git(repo, "show", f"{sha}:{path}")
    except GitError as e:
        message = str(e)
        if "does not exist" in message or "exists on disk, but not in" in message:
            return ABSENT
        finding.warnings.append(f"{path}@{sha[:8]}: snapshot unreadable ({message})")
        return UNREADABLE
    try:
        return parse_lockfile(text)
    except LockfileParseError as e:
        finding.warnings.append(f"{path}@{sha[:8]}: unreadable snapshot ({e})")
        return UNREADABLE


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


def _warn_once(finding: RepoFinding, warned: set[str], message: str) -> None:
    """Record a warning once per repo, however many refs re-encounter it."""
    if message not in warned:
        warned.add(message)
        finding.warnings.append(message)


def _scan_ref_chain(repo: Path, path: str, ref: str, chain: list[Commit],
                    query: WindowQuery, finding: RepoFinding,
                    seen: set[tuple], snapshots: dict[str, LockfileModel | str],
                    children: dict[str, list[str]], parents: dict[str, list[str]],
                    by_sha: dict[str, Commit], warned: set[str]) -> None:
    """Judge one ref's lockfile history, ancestors first.

    An interval starts at the pinning commit and ends at the first *descendant*
    that no longer pins a named version — including one that deleted the
    lockfile. Successors that are merely later in topological order but not
    descendants (a sibling branch) do not close it: widening an interval
    over-reports, truncating one hides exposure.
    """
    def snapshot(commit: Commit) -> LockfileModel | str:
        if commit.sha not in snapshots:
            snapshots[commit.sha] = _read_snapshot(repo, commit.sha, path, finding)
        return snapshots[commit.sha]

    for i, commit in enumerate(chain):
        model = snapshot(commit)
        if isinstance(model, str):
            continue
        bad = model.versions_of(query.package) & query.malicious_versions
        if not bad:
            continue

        until: datetime | None = None
        forward = _descendants(children, commit.sha)
        for successor in chain[i + 1:]:
            if successor.sha not in forward:
                continue
            later = snapshot(successor)
            if later is UNREADABLE:
                continue  # cannot claim the pin ended here
            if later is ABSENT or not (
                later.versions_of(query.package) & query.malicious_versions
            ):
                until = successor.late
                break
        since = commit.early

        # Half-open [since, until) against the inclusive window.
        if since > query.window_end or (until is not None and until <= query.window_start):
            continue
        # Only a commit dated before its own parent is skewed; two commits on
        # parallel branches appearing out of date order in a topological listing
        # is ordinary branching, not a clock problem.
        for parent_sha in parents.get(commit.sha, ()):
            parent = by_sha.get(parent_sha)
            if parent is not None and commit.early < parent.early:
                _warn_once(finding, warned,
                           f"{path}@{commit.sha[:8]}: commit predates its parent "
                           f"{parent_sha[:8]} (clock skew or rebase); interval "
                           "bounds are conservative")
        if commit.dates_diverge:
            _warn_once(finding, warned,
                       f"{path}@{commit.sha[:8]}: author/committer dates diverge by "
                       ">48h (history likely rewritten); dates used conservatively")
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
    warned: set[str] = set()
    try:
        if is_shallow(repo):
            finding.warnings.append(
                "shallow clone: history is truncated, absence of exposure is not evidence"
            )
        paths = lockfile_paths(repo)
        refs = _refs(repo)
        children, parents = _commit_graph(repo) if paths else ({}, {})
    except GitError as e:
        finding.warnings.append(str(e))
        return finding

    for path in paths:
        finding.lockfiles_seen += 1
        seen: set[tuple] = set()
        snapshots: dict[str, LockfileModel | str] = {}
        by_sha: dict[str, Commit] = {}
        any_history = False

        for ref in refs:
            try:
                chain = _log_commits(repo, path, ref=ref)
            except GitError as e:
                finding.warnings.append(f"{path}@{ref}: {e}")
                continue
            if chain:
                any_history = True
                by_sha.update({c.sha: c for c in chain})
                _scan_ref_chain(repo, path, ref, chain, query, finding, seen,
                                snapshots, children, parents, by_sha, warned)

        if not any_history:
            finding.warnings.append(
                f"{path}: discovered in refs but no walkable history (evidence unreadable)"
            )
    return finding
