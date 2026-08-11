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
- **A tree we cannot read is not a tree without exposure.** Only npm lockfiles
  are parsed. A tree locked with Yarn, pnpm, Bun or Deno is recorded in
  ``unread_trees`` and makes the repo INDETERMINATE —
  reporting CLEAN there would answer a question nobody could have looked at
  (found by replaying such repositories, see ``docs/experiments.md`` E12).
  Unlike a warning, it does not raise a grade: nothing suggests exposure either,
  so the honest outcome is "not judged".
- **A foreign lockfile counts during the window and only then.** Its existence
  interval is read from git even though its contents cannot be parsed, so a
  project that moved off Yarn years before the incident is not denied an
  all-clear forever (E13). Whether a ``package.json`` that *no* lockfile governed
  is likewise unread is a harder question than it looks — see issue #22.
- **Only the lockfile npm would have read testifies.** When a directory holds
  both ``npm-shrinkwrap.json`` and ``package-lock.json``, npm ignores the latter,
  so at those commits so do we; scanning both invents exposure from a file that
  was never installed.

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

# npm writes one of these two, and a published package ships the second; both use
# the same schema, so one parser reads either.
NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
# Lockfiles we can recognise but not parse yet (issue #17), and the tool that
# writes each. Finding one means that tree's installed versions are unknown to us.
# Every package manager that installs from the npm registry belongs here, because
# a name missing from this table is a repository this tool would call clean.
FOREIGN_LOCKFILES = {
    "yarn.lock": "Yarn",
    "pnpm-lock.yaml": "pnpm",
    "shrinkwrap.yaml": "pnpm (v3 and earlier)",
    "bun.lock": "Bun",
    "bun.lockb": "Bun",
    "deno.lock": "Deno",  # locks npm: specifiers alongside its own
}
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
        """Whether the ref that established this interval still pins the version.

        True for any ref, not just HEAD: a release branch whose tip still holds a
        compromised version is exactly what a remediation list must contain.
        """
        return self.until is None


@dataclass(frozen=True)
class UnreadTree:
    """A tree whose installed versions this tool could not read.

    ``path`` is the file that made this tree unreadable — a lockfile recognised
    but not parsed, or the ``package.json`` nothing locked. It is kept apart from
    ``reason`` so a caller can apply its own judgment about which trees matter: one
    under ``tests/fixtures`` is committed data, not something a workflow installs.

    ``commit`` is a commit where the tree was in this state during the window, so
    that judgment can be made against the workflows of the time rather than the
    workflows of today.
    """

    path: str
    reason: str
    commit: str = ""


@dataclass
class RepoFinding:
    """Everything the walker learned about one repository."""

    repo: Path
    exposures: list[Exposure] = field(default_factory=list)
    # Evidence that was lost: a truncated clone, an unreadable snapshot, a lockfile
    # that would not parse. Each one leaves a question open, so each one keeps the
    # repository from being cleared and widens what has to be rotated.
    warnings: list[str] = field(default_factory=list)
    # Observations about the history that cost no evidence — a rewritten date, a
    # commit older than its parent. They are printed, and that is all: treating
    # them as lost evidence put every credential of a rebased repository on the
    # rotation list (E14).
    diagnostics: list[str] = field(default_factory=list)
    # Ways this *clone* holds less than the repository does: shallow, partial,
    # single-branch. Kept apart from ``warnings`` because the remedy differs — a
    # deeper clone fixes these and nothing fixes a corrupt lockfile — and because
    # only these may be waived by ``--allow-incomplete-history``.
    incomplete: list[str] = field(default_factory=list)
    lockfiles_seen: int = 0
    # Trees whose dependencies this tool cannot read at all: a lockfile in a
    # dialect it does not parse, or a Node project with no lockfile in history.
    # Kept apart from ``warnings`` because the two deserve different answers —
    # a warning means evidence about a tracked lockfile was lost, so an install
    # is possible; an unread tree means there was never anything to look at.
    unread_trees: list[UnreadTree] = field(default_factory=list)

    @property
    def exposed(self) -> bool:
        return bool(self.exposures)

    @property
    def verdict(self) -> Verdict:
        """CLEAN is only claimable when nothing was exposed AND nothing went unread."""
        if self.exposures:
            return Verdict.EXPOSED
        if self.warnings or self.unread_trees or self.incomplete:
            return Verdict.INDETERMINATE
        return Verdict.CLEAN


def is_shallow(repo: Path) -> bool:
    return _git(repo, "rev-parse", "--is-shallow-repository").strip() == "true"


def _config(repo: Path, key: str) -> str:
    """One git config value, empty when unset. Never raises for a missing key."""
    result = subprocess.run(
        ["git", "-C", str(repo), "config", "--get-all", key],
        capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def incomplete_history(repo: Path) -> list[str]:
    """Every way this clone is known to hold less than the repository does.

    A shallow clone was already detected; two other truncations were not, and both
    produce a clean verdict from a history that was never there (E16):

    - a **partial clone** has the commits but not the blobs, so a snapshot read either
      fetches from the promisor remote one object at a time or fails
    - a **single-branch clone** has one ref, which makes "every ref testifies" false
      while nothing in the report says so

    Each is one config lookup, and each belongs in ``warnings`` so the repository
    cannot be cleared on evidence it does not have.
    """
    reasons = []
    if is_shallow(repo):
        reasons.append(
            "shallow clone: history is truncated, absence of exposure is not evidence"
        )
    if _config(repo, "remote.origin.promisor") == "true":
        filtered = _config(repo, "remote.origin.partialclonefilter") or "unknown filter"
        reasons.append(
            f"partial clone ({filtered}): lockfile contents are not all present "
            "locally, so what a snapshot pinned may not be readable"
        )
    fetch = _config(repo, "remote.origin.fetch")
    if fetch and "*" not in fetch:
        reasons.append(
            f"single-branch clone ({fetch}): the other refs are absent, and exposure "
            "on a branch nobody fetched is still exposure"
        )
    return reasons


def _paths_with_basename(repo: Path, basenames: tuple[str, ...]) -> list[str]:
    """Every path where one of these files ever lived on any ref.

    ``--diff-merges=first-parent`` is what makes a merge report its own change:
    without it git prints nothing for merge commits, so a lockfile introduced *by* a
    merge is never discovered at all — measured on a repository whose ``yarn.lock``
    sits at HEAD and was reported clean (E16). ``--no-renames`` keeps rename
    detection from collapsing "package-lock deleted, npm-shrinkwrap added" into one
    record, which would hide a precedence handover, and keeps discovery working on a
    partial clone where similarity detection would need absent blobs.

    ``-z`` output is unquoted and NUL-separated, so it is split on NUL and nothing
    else: rewriting newlines as separators turned ``line\\nbreak/package-lock.json``
    into a file called ``break/package-lock.json``, which was then reported as
    unwalkable (E14). The basename check rejects look-alikes such as
    ``sample-package-lock.json``, which the ``*name`` pathspec would match.
    """
    out = _git(repo, "log", "--all", "--full-history", "--diff-merges=first-parent",
               "--no-renames", "--format=", "--name-only", "-z",
               "--", *(f"*{name}" for name in basenames))
    wanted = set(basenames)
    names = {token[1:] if token.startswith("\n") else token
             for token in out.split("\0") if token.strip("\n")}
    return sorted(n for n in names if posixpath.basename(n) in wanted)


def discovered_lockfiles(repo: Path) -> tuple[list[str], list[str]]:
    """Lockfiles this tool can parse, and lockfiles it can only recognise.

    Both come from one history walk, because walking twice doubles the cost of
    the most expensive part of a scan.
    """
    found = _paths_with_basename(repo, (*NPM_LOCKFILES, *FOREIGN_LOCKFILES))
    npm = [p for p in found if posixpath.basename(p) in set(NPM_LOCKFILES)]
    foreign = [p for p in found if posixpath.basename(p) in FOREIGN_LOCKFILES]
    return npm, foreign


def lockfile_paths(repo: Path) -> list[str]:
    """Every npm lockfile path in this repository's history."""
    return discovered_lockfiles(repo)[0]


def _exists_at(repo: Path, sha: str, path: str) -> bool:
    """Whether ``path`` is present in one commit's tree.

    Asked of the tree rather than of the blob. ``cat-file -e <sha>:<path>`` needs the
    blob itself, so on a partial clone it either triggers a per-object fetch from the
    promisor remote or, with lazy fetching disabled, answers "missing" for a file that
    is plainly in the tree. Trees are never filtered out by ``blob:none``, so
    ``ls-tree`` answers from local data and cannot be wrong in that direction.
    """
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-z", "--name-only", sha, "--", path],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and bool(result.stdout.strip("\0"))


def _existed_during(repo: Path, path: str, query: WindowQuery,
                    refs: list[str], children: dict[str, list[str]],
                    present: dict[tuple[str, str], bool]) -> str | None:
    """A commit witnessing ``path`` in the tree while the window was open.

    A file's *contents* may be unreadable — a Yarn lockfile, a binary lock — but
    *when it was there* is always readable from git, and a file deleted before the
    window or added after it says nothing about the window.

    Every ref is asked separately and any one of them answering is enough: a
    deletion on ``main`` says nothing about a branch that still carries the file
    and is still built. Within a ref an interval ends at the first *descendant*
    that no longer has the file, so a sibling line cannot truncate it. The window
    test is the one exposures use, so a file present at the closing instant counts.
    """
    def here(sha: str) -> bool:
        key = (sha, path)
        if key not in present:
            present[key] = _exists_at(repo, sha, path)
        return present[key]

    for ref in refs:
        commits = _log_commits(repo, path, ref=ref)
        for i, commit in enumerate(commits):
            if not here(commit.sha):
                continue
            end: datetime | None = None
            forward = _descendants(children, commit.sha)
            for successor in commits[i + 1:]:
                if successor.sha in forward and not here(successor.sha):
                    end = successor.late
                    break
            if commit.early > query.window_end:
                continue
            if end is not None and end <= query.window_start:
                continue
            return commit.sha
    return None



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
                 all_refs: bool = False, also: tuple[str, ...] = ()) -> list[Commit]:
    """Commits touching one path, ancestors first, in git's topological order.

    Topological order (not date order) is what makes interval reasoning sound:
    a parent always precedes its descendants regardless of what the clocks said.

    ``--full-history`` is not optional. Git's default history simplification follows
    only one parent of a merge that is TREESAME to it, so a branch that pinned a
    malicious version and lost the merge conflict disappears from the log entirely —
    a repository whose CI built that branch reported exit 0 (E15). The flag costs
    extra commits, every one of which is judged on its own snapshot, so a superset
    can only improve the answer.

    ``also`` widens the log to commits that touched another path instead. It exists
    for precedence: removing a shrinkwrap puts the package-lock beside it back in
    charge without touching that file, so a log of the package-lock alone never
    sees the moment it started to matter (E14).
    """
    args = ["log", "--topo-order", "--full-history", "--no-renames",
            "--format=%H|%aI|%cI"]
    if all_refs:
        args.append("--all")
    if ref:
        args.append(ref)
    args += ["--", path, *also]
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


def _note_once(finding: RepoFinding, warned: set[str], message: str) -> None:
    """Record a diagnostic once per repo, however many refs re-encounter it."""
    if message not in warned:
        warned.add(message)
        finding.diagnostics.append(message)


def _scan_ref_chain(repo: Path, path: str, ref: str, chain: list[Commit],
                    query: WindowQuery, finding: RepoFinding,
                    seen: set[tuple], snapshots: dict[str, LockfileModel | str],
                    children: dict[str, list[str]], parents: dict[str, list[str]],
                    by_sha: dict[str, Commit], warned: set[str],
                    shadowed_by: str | None = None) -> None:
    """Judge one ref's lockfile history, ancestors first.

    An interval starts at the pinning commit and ends at the first *descendant*
    that no longer pins a named version — including one that deleted the
    lockfile. Successors that are merely later in topological order but not
    descendants (a sibling branch) do not close it: widening an interval
    over-reports, truncating one hides exposure.

    ``shadowed_by`` names a lockfile that takes precedence over this one; at any
    commit where it exists, this file is what npm ignored, so it testifies to
    nothing.
    """
    def snapshot(commit: Commit) -> LockfileModel | str:
        if commit.sha not in snapshots:
            snapshots[commit.sha] = _read_snapshot(repo, commit.sha, path, finding)
        return snapshots[commit.sha]

    def shadowed(sha: str) -> bool:
        """Whether the file taking precedence over this one exists at that commit."""
        return shadowed_by is not None and _exists_at(repo, sha, shadowed_by)

    for i, commit in enumerate(chain):
        if shadowed(commit.sha):
            continue
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
            if shadowed(successor.sha):
                # npm stopped reading this file here, so the pin stopped mattering
                # here. Without this the interval stayed open and the report said
                # "still pinned" about a lockfile nothing installs (E14).
                until = successor.late
                break
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
                _note_once(finding, warned,
                           f"{path}@{commit.sha[:8]}: commit predates its parent "
                           f"{parent_sha[:8]} (clock skew or rebase); interval "
                           "bounds are conservative")
        if commit.dates_diverge:
            _note_once(finding, warned,
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
        finding.incomplete.extend(incomplete_history(repo))
        paths, foreign = discovered_lockfiles(repo)
        refs = _refs(repo)
        children, parents = _commit_graph(repo) if paths or foreign else ({}, {})
        # A foreign lockfile only says something about the window if it was there
        # during it: holding one committed years earlier against a project denied
        # an all-clear forever (E13).
        present: dict[tuple[str, str], bool] = {}
        live_foreign = {
            path: witness for path in foreign
            if (witness := _existed_during(repo, path, query, refs, children, present))
        }
    except GitError as e:
        finding.warnings.append(str(e))
        return finding

    for path, witness in live_foreign.items():
        tool = FOREIGN_LOCKFILES[posixpath.basename(path)]
        finding.unread_trees.append(UnreadTree(
            path=path,
            reason=f"{path}: {tool} lockfiles are not parsed yet, so the versions this "
                   "tree installed were not judged",
            commit=witness,
        ))

    for path in paths:
        finding.lockfiles_seen += 1
        seen: set[tuple] = set()
        snapshots: dict[str, LockfileModel | str] = {}
        by_sha: dict[str, Commit] = {}
        any_history = False
        # npm ignores package-lock.json entirely when a shrinkwrap sits beside it,
        # so judging both independently would invent an exposure from a file npm
        # never read.
        shadowed_by = None
        if posixpath.basename(path) == "package-lock.json":
            sibling = posixpath.join(posixpath.dirname(path), "npm-shrinkwrap.json")
            shadowed_by = sibling if sibling in paths else None

        for ref in refs:
            try:
                # Reuse the log the coverage pass already read, unless precedence
                # needs the wider one: a git log per file per ref is what a monorepo
                # scan spends its time on.
                chain = _log_commits(repo, path, ref=ref,
                                     also=(shadowed_by,) if shadowed_by else ())
            except GitError as e:
                finding.warnings.append(f"{path}@{ref}: {e}")
                continue
            if chain:
                any_history = True
                by_sha.update({c.sha: c for c in chain})
                _scan_ref_chain(repo, path, ref, chain, query, finding, seen,
                                snapshots, children, parents, by_sha, warned,
                                shadowed_by=shadowed_by)

        if not any_history:
            finding.warnings.append(
                f"{path}: discovered in refs but no walkable history (evidence unreadable)"
            )
    return finding
