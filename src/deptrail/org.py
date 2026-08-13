"""Scan a whole organization for one advisory and merge the answers into a report.

An incident is answered per organization, not per repository: the responder needs
one timeline of what happened where, and one rotation list. Two rules shape this
module.

**A repository that could not be scanned is reported, never skipped.** A crash, a
missing clone, or an unreadable history appears in ``errors`` and keeps the
report's verdict from claiming completeness — silence would read as "clean" for
exactly the repository nobody looked at.

**The advisory's own caveat travels with the result.** A partial feed cannot prove
absence, so ``OrgReport.proves_absence`` is false whenever the plan says so or any
repository failed, and the report says which.

**Fixture lockfiles are set aside, never dropped.** A lockfile under
``tests/fixtures`` or ``examples`` is committed data, not a dependency any CI
installs, and letting it raise credentials for rotation would bury the real items
(measured on this project's own repository).
Such exposures stay in the report under their own heading with the reason, so a
human can overrule the classification; they simply do not produce rotation items.
"""
from __future__ import annotations

import re
import subprocess
import textwrap
from enum import Enum
from functools import lru_cache
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

from .grading import (
    INSTALL_COMMANDS,
    Grade,
    GradedExposure,
    GradedFinding,
    RunHistory,
    ToolFailure,
    grade_finding,
)
from .history import (
    Exposure,
    GitError,
    UnreadTree,
    Verdict,
    _git as _git_text,
    scan_repo,
)
from .ioc import QueryPlan
from .rotation import (
    Caveat,
    RepoRotation,
    RotationItem,
    Scope,
    merge_caveats,
    rotation_for_repo,
)

RunsProvider = Callable[[Path, str], RunHistory]
SecretsProvider = Callable[[Path, str], tuple[str, ...]]  # returns names; raise if unavailable

# Directory names whose lockfiles are test data or documentation rather than a
# tree any workflow installs.
NON_DEPLOYED_DIRS = frozenset({
    "test", "tests", "spec", "specs", "fixture", "fixtures", "__fixtures__",
    "testdata", "example", "examples", "sample", "samples", "demo", "demos",
    "node_modules", "vendor",
})


# How much a scope widens the rotation list; merging keeps the widest.
SCOPE_WIDTH = {Scope.WORKFLOW: 0, Scope.DEVELOPER: 1, Scope.REPO_WIDE: 2}


def is_probably_installed(lockfile_path: str) -> bool:
    """Whether a workflow would plausibly install this lockfile.

    A root lockfile, or one in a workspace directory, is installed. One under a
    fixture or example directory is committed data — flagging it would inflate a
    rotation list with credentials nothing ever exposed.
    """
    directories = PurePosixPath(lockfile_path).parts[:-1]
    return not any(part.lower() in NON_DEPLOYED_DIRS for part in directories)


class Installed(str, Enum):
    """Whether a workflow installs a tree — and the third answer, which is not "no".

    Forced into a boolean this was wrong four times, in both directions. A bare substring
    made `"test"` match `ubuntu-latest` and a fixture look installed; requiring an install
    command on the same line made a real ``npm ci --prefix examples/app`` reached through a
    composite action look like test data. Every attempt to decide *whether a workflow
    installs a directory* by pattern-matching YAML was wrong somewhere, in both directions
    at once by the fourth try — an install can arrive through a composite action, a wrapper
    script, a matrix variable, `npm i`, a bare `yarn`, or a reusable workflow in another
    repository, and a directory name can appear in a step title, a runner label or an
    echoed string.

    So that question is not asked here. What is asked is narrower and answerable: does a
    workflow at that commit **name** this directory as a path? If it does and a run is
    implicated, the tree is installed. If it does and no run is implicated, the answer is
    ``UNKNOWN`` — which is the case that used to be silently "no", and that silence is
    what deleted a finding when CI evidence weakened.
    """

    YES = "YES"
    NO = "NO"
    UNKNOWN = "UNKNOWN"


def _mentions(text: str, directory: str) -> bool:
    """Whether the text names this directory as a path, rather than inside another word.

    Compared as path segments, not by substring or by a boundary regex. Both of those were
    wrong on real input: `"test"` matched `ubuntu-latest`, and a regex boundary still
    matched `vendor/examples/app` and `examples/app.bak` when the tree was `examples/app`.
    """
    wanted = PurePosixPath(directory)
    for token in re.findall(r"[\w./-]+", text):
        candidate = token.strip("'\"").lstrip("./")
        if not candidate:
            continue
        path = PurePosixPath(candidate)
        if path == wanted or wanted in path.parents:
            return True
    return False


def _workflow_mentions_dir(repo: Path, sha: str, paths: tuple[str, ...],
                           directory: str) -> bool:
    """Whether any of these workflows names this lockfile's directory."""
    if not directory or directory == ".":
        return False
    for path in paths:
        body = _text_at(repo, sha, path)
        if body is not None and _mentions(body, directory):
            return True
    return False


@lru_cache(maxsize=1024)
def _text_at_cached(repo: str, sha: str, path: str) -> str | None:
    try:
        return _git_text(Path(repo), "show", f"{sha}:{path}")
    except GitError:
        return None


def _text_at(repo: Path, sha: str, path: str) -> str | None:
    """One blob at one commit, read once, keyed on a ref that fixes the content.

    Uncached, classifying one exposure per lockfile per advisory package re-read every
    workflow every time: 780 git subprocesses and a 12x wall clock on a repository with
    thirty fixture lockfiles, for a byte-identical answer.

    The ref has to be resolved to an object id first. Judging it by shape does not work —
    a branch may be named ``deadbeef`` — and caching a name that can move means answering
    from before it moved.
    """
    resolved = _object_id(repo, sha)
    if resolved is None:
        try:
            return _git_text(repo, "show", f"{sha}:{path}")
        except GitError:
            return None
    return _text_at_cached(str(repo), resolved, path)


@lru_cache(maxsize=1024)
def _object_id(repo: Path, ref: str) -> str | None:
    """The immutable id ``ref`` points at, or ``None`` if it cannot be resolved.

    Cached on the pair, which is safe in the direction that matters: a name that moves
    would be re-resolved by a fresh process, and within one scan the commit under
    examination does not change. A ref that does not resolve is not cached as an answer.
    """
    try:
        return _git_text(repo, "rev-parse", f"{ref}^{{commit}}").strip() or None
    except GitError:
        return None


def _classify_tree(repo: Path, graded: GradedExposure) -> Installed:
    """Whether this exposure sits in a tree some workflow would have installed.

    ``UNKNOWN`` is the answer that was missing. A workflow naming the directory is
    evidence about the tree; whether that workflow *ran* is evidence about CI, and the two
    were conflated. So losing a run record used to turn "installed" into "not installed"
    and delete the finding — measured at exit 0 with ``scan_complete: true`` for a
    repository whose CI demonstrably installed the malicious version. Weakened evidence
    must weaken a grade, never remove a finding.
    """
    lockfile = graded.exposure.lockfile_path
    if is_probably_installed(lockfile):
        return Installed.YES
    directory = str(PurePosixPath(lockfile).parent)
    sha = graded.exposure.commit
    # Installed only where a run is implicated *and* its own workflow names the directory:
    # what another workflow does is not evidence about the run that happened.
    if graded.grade is Grade.CONFIRMED and _workflow_mentions_dir(
            repo, sha, graded.workflow_paths, directory):
        return Installed.YES
    # But any workflow at that commit naming it is enough to withhold a clearance, even one
    # that did not run here — it could on the next push, and the run records that would
    # show it are exactly what may be missing. Under stronger CI evidence this tree would
    # have been kept, so answering "test data" would make the classification a function of
    # what the runs API happened to return.
    if _workflow_mentions_dir(repo, sha, _workflows_at(repo, sha), directory):
        return Installed.UNKNOWN
    return Installed.NO


def _is_installed_tree(repo: Path, graded: GradedExposure) -> bool:
    """Whether this tree is known to be installed. ``UNKNOWN`` is not that."""
    return _classify_tree(repo, graded) is Installed.YES


def _workflows_at(repo: Path, sha: str) -> tuple[str, ...]:
    """Workflow files as they stood at one commit.

    Read at the commit and not at HEAD: a workflow that installed a directory
    during the window and was deleted afterwards is exactly the evidence that
    matters, and looking at today's tree loses it.
    """
    listing = _tree_at(str(repo), sha)
    return tuple(line for line in listing.splitlines() if line.strip())


@lru_cache(maxsize=1024)
def _tree_at(repo: str, sha: str) -> str:
    try:
        return _git_text(Path(repo), "ls-tree", "-r", "--name-only", sha,
                         ".github/workflows")
    except GitError:
        return ""


def _is_installed_unread_tree(repo: Path, tree: UnreadTree) -> bool:
    """Whether an unread tree is one a workflow would have installed.

    The directory heuristic must lose to evidence here for the same reason it does
    for exposures: an application that really lives under ``examples/`` would
    otherwise be filed away as sample data, and the repository would be cleared on
    the strength of a directory name (found by review).
    """
    if is_probably_installed(tree.path):
        return True
    directory = str(PurePosixPath(tree.path).parent)
    if not directory or directory == ".":
        return True
    sha = tree.commit or "HEAD"
    return _workflow_mentions_dir(repo, sha, _workflows_at(repo, sha), directory)


# Failures that mean the tooling could not answer, as opposed to evidence that says
# nothing. Retrying one of these may help; retrying a corrupt lockfile will not.
TRANSIENT_FAILURES = (OSError, subprocess.CalledProcessError, ToolFailure, GitError)


def _record_failure(report: "OrgReport", where: str, error: Exception) -> None:
    """File a failure under the heading that tells a caller what to do about it."""
    line = f"{where} ({type(error).__name__}: {error})"
    target = (report.transient if isinstance(error, TRANSIENT_FAILURES)
              else report.errors)
    target.append(line)


@dataclass(frozen=True)
class TimelineEntry:
    """One exposure, placed in the organization-wide order of events."""

    repo: str
    package: str
    exposure: Exposure
    grade: Grade
    evidence: tuple[str, ...]
    run_ids: tuple[str, ...] = ()
    probably_installed: bool = True
    # Neither installed nor cleared. Kept apart from ``probably_installed`` being False,
    # which is a statement that nothing installs this tree — the two were the same flag,
    # so one exposure appeared under "fixture or example trees, not installed by any
    # workflow" and under "could not classify" at once, and counted toward neither grade.
    unresolved: bool = False


@dataclass
class OrgReport:
    """What one advisory did to one organization."""

    advisory_id: str
    advisory_name: str
    findings: list[GradedFinding] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    rotations: list[RepoRotation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Failures of the tooling rather than of the evidence: an absent `git`/`gh`, a
    # failed API call, a clone that did not complete. Separate from ``errors``
    # because only these are worth retrying, and because a caller that sees a
    # verdict-shaped exit code would never learn the tool did not finish.
    transient: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Trees nothing could be said about, as "repo: reason". Distinct from
    # ``errors``: the scan worked, there was simply no lockfile it could read.
    unread: list[str] = field(default_factory=list)
    # Repositories whose clone held less than the repository does, as
    # "repo: reason". A deeper clone is the remedy, so the report says which.
    incomplete: list[str] = field(default_factory=list)
    # Exposures in a tree that could not be classified: a workflow might install it
    # through something unreadable. Kept out of the rotation list — a fixture must not
    # raise credentials — and out of an all-clear, because "could not tell" is not "no".
    unresolved: list[str] = field(default_factory=list)
    repos_scanned: int = 0
    partial_coverage: bool = False

    @property
    def exposed_repos(self) -> tuple[str, ...]:
        """Repos with an exposure in a tree a workflow would install."""
        return tuple(sorted({e.repo for e in self.timeline if e.probably_installed}))

    @property
    def set_aside(self) -> tuple[TimelineEntry, ...]:
        """Exposures in fixture or example trees, kept visible but not rotated.

        Only those a workflow demonstrably does not install. One it *might* install is a
        different statement and has its own section.
        """
        return tuple(e for e in self.timeline
                     if not e.probably_installed and not e.unresolved)

    @property
    def unclassified(self) -> tuple[TimelineEntry, ...]:
        """Exposures whose tree could be installed by something unreadable."""
        return tuple(e for e in self.timeline if e.unresolved)

    @property
    def rotation_items(self) -> tuple[RotationItem, ...]:
        """Every credential to rotate, once each, worst grade first.

        One credential can be implicated by several packages of the same advisory
        and by several lockfiles in the same repo. A responder rotates it once, so
        the duplicates are merged and the strongest grade and every run id are
        kept — otherwise the count at the top of the report is simply wrong.
        """
        order = {Grade.CONFIRMED: 0, Grade.LIKELY: 1, Grade.POSSIBLE: 2}
        merged: dict[tuple[str, str], RotationItem] = {}
        for rotation in self.rotations:
            for item in rotation.items:
                key = (item.repo, item.secret)
                existing = merged.get(key)
                if existing is None:
                    merged[key] = item
                    continue
                stronger = min(existing, item, key=lambda i: order.get(i.grade, 3))
                # Widest scope wins regardless of the order the items arrived in.
                widest = max((existing.scope, item.scope), key=SCOPE_WIDTH.get)
                # Merged on the sentence, not on prose split at "; ": the same
                # sentence about another version collapses and keeps both versions,
                # while clause-level deduplication used to eat the tail of every
                # sentence after the first — the second package's reason ended at
                # "outside CI" with its advice removed (#30).
                merged[key] = replace(
                    stronger, scope=widest,
                    causes=merge_caveats([*existing.causes, *item.causes]),
                    run_ids=tuple(sorted(set(existing.run_ids) | set(item.run_ids))),
                )
        return tuple(sorted(merged.values(),
                            key=lambda i: (order.get(i.grade, 3), i.repo, i.secret)))

    @property
    def unnamed_repos(self) -> tuple[str, ...]:
        """Repositories at risk whose secret names could not be listed.

        Counted separately from the items, because they are the part of the rotation
        list no headline number can cover.
        """
        return tuple(sorted({r.repo for r in self.rotations if r.unnamed}))

    def requires_rotation(self, items: tuple[RotationItem, ...] | None = None) -> bool:
        """Whether a responder has credentials to act on.

        True when items were named *or* a repository's credentials are at risk but
        could not be listed — an empty item list is not an all-clear.

        Takes the items when a caller already has them. ``rotation_items`` is a merge
        quadratic in the items, and a caller that needs both the list and this answer
        would otherwise pay for it twice; the rule itself lives here so the two
        cannot drift apart.
        """
        if items is None:
            items = self.rotation_items
        return bool(items) or any(r.unnamed for r in self.rotations)

    @property
    def rotation_required(self) -> bool:
        """``requires_rotation`` for callers that do not hold the items."""
        return self.requires_rotation()

    def _grouped(self, pick: Callable[[RepoRotation], Iterable[Caveat]],
                 ) -> tuple[str, ...]:
        """Caveats gathered per repository and merged, one line each.

        Gathered across ``rotations`` and not within one, because a repository has
        one entry there per advisory *package*: merging inside each entry would
        leave the copies untouched, which is how the same paragraph came to be
        printed once per package.
        """
        per_repo: dict[str, list[Caveat]] = {}
        for rotation in self.rotations:
            per_repo.setdefault(rotation.repo, []).extend(pick(rotation))
        return tuple(f"{repo}: {caveat.rendered}"
                     for repo, caveats in per_repo.items()
                     for caveat in merge_caveats(caveats))

    @property
    def unnamed_rotations(self) -> tuple[str, ...]:
        """Repositories whose credentials must be rotated but could not be named."""
        return self._grouped(lambda r: r.unnamed)

    @property
    def rotation_notes(self) -> tuple[str, ...]:
        """Per-repository caveats, merged, prefixed with the repo they came from."""
        return self._grouped(lambda r: (*r.unnamed, *r.notes))

    @property
    def caveats(self) -> tuple[str, ...]:
        """Every caveat once, minus the lines a dedicated section already carries.

        One property for all three renderers. They each built this list themselves
        and drifted: the JSON output counted every gap twice for a while, because
        its ``caveats`` key repeated what ``not_judged`` already held.
        """
        shown = {*self.unread, *self.incomplete, *self.unnamed_rotations}
        return tuple(c for c in (*self.notes, *self.rotation_notes) if c not in shown)

    @property
    def worst_grade(self) -> Grade:
        """The strongest grade anywhere in the report, including repos whose
        history could not be read — those carry POSSIBLE with no timeline entry."""
        # An exposure that could not be classified counts too: it was found, and nothing
        # ruled it out. Excluding it left a report whose worst grade was NO_EVIDENCE while
        # naming a compromised version it had just declined to clear.
        grades = [e.grade for e in self.timeline
                  if e.probably_installed or e.unresolved]
        grades += [f.worst_grade for f in self.findings]
        for grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE):
            if grade in grades:
                return grade
        return Grade.NO_EVIDENCE

    @property
    def proves_absence(self) -> bool:
        """Whether "nothing found" may be reported as an all-clear.

        False if any repository failed to scan, if any tree could not be read, or
        if the advisory only covers part of the incident: in each case something
        was not looked at.
        """
        # Each reason is checked on its own, because an exposure wins the verdict:
        # a repository where one tree was read and exposed while another was
        # unreadable is EXPOSED, and that verdict must not be mistaken for having
        # seen everything. Both an unread tree and a lost snapshot leave a
        # question open regardless of what the aggregate verdict became.
        readable = all(f.verdict is not Verdict.INDETERMINATE and not f.warnings
                       for f in self.findings)
        # And nothing may have been *found*. This is the sentence the exit code speaks —
        # code 0 says "absence of exposure was established" — so an exposure in the
        # timeline contradicts it outright, however little can be done about it. Without
        # this, a repository holding a compromised version whose credentials could not be
        # named exited 0: no rotation item to raise the code to 1, and no unread tree or
        # truncated clone to lower it to 2.
        return (not self.errors and not self.transient and not self.partial_coverage
                and readable and not self.unread and not self.incomplete
                and not self.unresolved and not self.exposed_repos)


def scan_organization(repos: Iterable[tuple[str, Path]], plan: QueryPlan, *,
                      runs: RunsProvider, secrets: SecretsProvider | None = None,
                      allow_incomplete: bool = False) -> OrgReport:
    """Judge every repository against every package the advisory names.

    ``repos`` are (name, local clone path) pairs; ``runs`` and ``secrets`` are
    injected so the scan is testable without a network and so a caller can supply
    cached data for a large organization.
    """
    report = OrgReport(advisory_id=plan.advisory_id, advisory_name=plan.advisory_name,
                       partial_coverage=not plan.proves_absence)
    if plan.coverage_warning:
        report.notes.append(plan.coverage_warning)

    for name, path in repos:
        report.repos_scanned += 1
        if not (path / ".git").exists():
            report.errors.append(f"{name}: {path} is not a git repository")
            continue
        run_cache: dict[str, RunHistory] = {}
        secret_cache: dict[str, tuple[str, ...] | None] = {}
        for entry in plan.entries:
            query = entry.query
            try:
                finding = scan_repo(path, query)
            except Exception as e:  # a failed repo must be visible, not silent
                _record_failure(report, f"{name} ({query.package})", e)
                continue
            if name not in run_cache:
                try:
                    run_cache[name] = runs(path, name)
                except Exception as e:
                    # Losing the CI evidence must not lose the exposures already
                    # read from git: without runs every exposure is POSSIBLE, which
                    # is exactly what an unanswered question deserves. It must also
                    # not read as a verdict — a call that failed is a call to retry.
                    _record_failure(report, f"{name}: CI runs unavailable", e)
                    run_cache[name] = RunHistory(source=f"unavailable for {name}")
            history = run_cache[name]
            graded = grade_finding(
                finding, query, history,
                advisory_id=plan.advisory_id, coverage_warning=plan.coverage_warning,
            )
            classified = [(g, _classify_tree(path, g)) for g in graded.graded]
            report.timeline.extend(
                TimelineEntry(
                    repo=name, package=query.package, exposure=g.exposure,
                    grade=g.grade, evidence=g.evidence, run_ids=g.run_ids,
                    probably_installed=answer is Installed.YES,
                    unresolved=answer is Installed.UNKNOWN,
                )
                for g, answer in classified
            )
            for g, answer in classified:
                if answer is not Installed.UNKNOWN:
                    continue
                # Neither acted on nor cleared. Raising credentials here would put a
                # fixture's secrets on the list every time a repository uses a composite
                # action anywhere; staying silent would clear a tree a workflow may well
                # install. So it is named, and the report stops short of proving absence.
                line = (f"{name}: {g.exposure.lockfile_path} — a workflow at "
                        f"{g.exposure.commit[:8]} could install this tree through "
                        "something this tool does not read (a local action, a script, or "
                        "a directory chosen at run time), so it was neither acted on nor "
                        "cleared")
                if line not in report.unresolved:
                    report.unresolved.append(line)
            kept = [g for g, answer in classified if answer is Installed.YES]
            # The verdict has to be recomputed for the kept set: a repo whose only
            # exposures are fixtures but whose history was unreadable is still
            # INDETERMINATE, and carrying the original EXPOSED verdict here would
            # drop its repo-wide rotation items.
            # An unparsed lockfile under tests/fixtures is committed data like any
            # other: it must not cost the whole repository its verdict, or every
            # tooling project that keeps such a fixture would be told its scan
            # proves nothing.
            # An incomplete clone stops an all-clear unless the caller took
            # responsibility for it, in which case it stays visible as a caveat.
            if allow_incomplete and graded.incomplete:
                for reason in graded.incomplete:
                    # The guard has to test the line it appends: comparing the
                    # unsuffixed text let one gap print once per advisory package,
                    # which on a real advisory is hundreds of identical lines.
                    line = f"{name}: {reason} — accepted with --allow-incomplete-history"
                    if line not in report.notes:
                        report.notes.append(line)
                graded = replace(graded, incomplete=[])
            for reason in graded.incomplete:
                line = f"{name}: {reason}"
                if line not in report.incomplete:
                    report.incomplete.append(line)
            unread = [t for t in graded.unread_trees
                      if _is_installed_unread_tree(path, t)]
            set_aside_unread = [t for t in graded.unread_trees if t not in unread]
            installed = replace(
                graded, graded=kept, unread_trees=unread,
                verdict=(Verdict.EXPOSED if kept
                         # Only the walker's own findings mean the history was not
                         # read; a thin CI record does not.
                         else Verdict.INDETERMINATE
                         if graded.warnings or unread or graded.incomplete
                         else Verdict.CLEAN),
            )
            for tree in unread:
                line = f"{name}: {tree.reason}"
                if line not in report.unread:
                    report.unread.append(line)
            for tree in set_aside_unread:
                # Visible, but not part of the verdict — the same treatment a
                # fixture exposure gets.
                note = (f"{name}: {tree.reason} — set aside, nothing installs this "
                        "tree")
                if note not in report.notes:
                    report.notes.append(note)
            # The report keeps the finding the decisions were made on, so its
            # verdict is the one `proves_absence` must answer to.
            report.findings.append(installed)
            if installed.needs_rotation:
                if name not in secret_cache:
                    secret_cache[name] = None
                    if secrets:
                        try:
                            secret_cache[name] = secrets(path, name)
                        except Exception as e:
                            # One repo's secret listing failing must not lose the
                            # findings already collected for the rest.
                            _record_failure(
                                report, f"{name}: secret names unavailable", e)
                report.rotations.append(
                    rotation_for_repo(path, name, installed, secret_cache[name])
                )

    report.timeline.sort(key=lambda e: (e.exposure.since, e.repo))
    return report


# A terminal report is read in a terminal. Merging the duplicate paragraphs put
# every implicated version on one line, and on a 180-package advisory that line
# measured 3.3 kB — unreadable for the same reason the repetition was.
BODY_WIDTH = 96
# Below this, a line holds a word or two and folding stops helping. A prefix that
# leaves less than this gets its own line instead of pushing the body past the
# width: an ordinary repository and secret name reached 149 columns that way.
MIN_BODY = 32


def _folded(prefix: str, body: str, indent: str) -> list[str]:
    """One report line, folded to a readable width under a hanging indent.

    The prefix is emitted verbatim — a column of aligned grades stays aligned — and
    counts against the width. When it is long enough to leave no useful room, it
    takes a line of its own and the body follows at the indent, because an identity
    is not foldable: a repository or secret name has to stay in one piece.

    Words are never broken, so a secret name, a flag or a ``package@version``
    survives intact for whoever greps the output. That is a deliberate trade against
    the width: since the continuation indent counts, a token longer than
    ``BODY_WIDTH - len(indent)`` is kept whole and its line runs over. A path
    containing whitespace is not one token and is the case this cannot keep.
    """
    if len(prefix) + MIN_BODY > BODY_WIDTH:
        folded = textwrap.wrap(body, width=BODY_WIDTH, initial_indent=indent,
                              subsequent_indent=indent, break_long_words=False,
                              break_on_hyphens=False)
        return [prefix.rstrip(), *folded] if folded else _bare(prefix)
    return textwrap.wrap(body, width=BODY_WIDTH, initial_indent=prefix,
                         subsequent_indent=indent, break_long_words=False,
                         break_on_hyphens=False) or _bare(prefix)


def _bare(prefix: str) -> list[str]:
    """The prefix alone, or no line at all when there is not even that.

    A blank line here would land *inside* a section, and this project's own tooling
    reads its terminal output as blank-line-delimited sections.
    """
    return [prefix.rstrip()] if prefix.strip() else []


def _rotate_summary(items: tuple[RotationItem, ...], repos: tuple[str, ...]) -> str:
    """What the rotate heading claims, covering both halves of the list.

    A count of named credentials alone reads as the whole job when a second
    repository's secrets are at risk and unlistable, so the heading says both.

    Takes the already-computed values rather than the report: ``rotation_items`` is
    an incremental merge that is quadratic in the items, and re-deriving it here
    made one render of a 180-package scan compute it three times.
    """
    parts = []
    if items:
        parts.append(f"{len(items)} credential(s)")
    if repos:
        parts.append(f"{len(repos)} repositor{'y' if len(repos) == 1 else 'ies'} "
                     "to rotate broadly")
    return ", ".join(parts)


def render_report(report: OrgReport, advisory=None) -> str:
    """A terminal report: the timeline, then the rotation list, then the caveats.

    The advisory is optional but wanted: this is the format the composite action writes
    to its step summary, and without it the report never showed the window at all — so a
    reader could not tell a window known to have closed from one still open, which is the
    difference between "this cannot have been installed since" and "it still can".
    """
    lines = [
        f"advisory {report.advisory_id} — {report.advisory_name}",
        f"scanned {report.repos_scanned} repo(s); worst grade {report.worst_grade.value}",
    ]
    if advisory is not None:
        start, end = advisory.window
        closed = ("still open — no removal time is recorded, so exposure cannot be "
                  "ruled out after this" if end is None else end.isoformat())
        lines += _folded(f"installable window {start.isoformat()} → ", closed, " " * 4)
    lines.append("")
    installed = [e for e in report.timeline if e.probably_installed]
    if installed:
        lines.append("timeline")
        for entry in installed:
            until = (f"{entry.exposure.until:%Y-%m-%d %H:%M}"
                     if entry.exposure.until else "still pinned")
            lines.append(
                f"  [{entry.grade.value:11s}] {entry.repo}: "
                f"{entry.package}@{entry.exposure.version} in "
                f"{entry.exposure.lockfile_path} "
                f"{entry.exposure.since:%Y-%m-%d %H:%M} → {until}"
            )
            for fact in entry.evidence:
                lines.append(f"                {fact}")
    elif report.unread or report.incomplete:
        # Saying "no exposure found" alone would read as an all-clear for a
        # repository whose dependencies were never legible, or whose clone held less
        # than the repository does.
        lines.append("timeline: no exposure found in what could be read")
    else:
        lines.append("timeline: no exposure found in an installed tree")
    lines.append("")

    if report.set_aside:
        lines.append(f"set aside ({len(report.set_aside)}) — fixture or example trees, "
                     "not installed by any workflow")
        for entry in report.set_aside:
            lines.append(f"  [{entry.grade.value:11s}] {entry.repo}: "
                         f"{entry.package}@{entry.exposure.version} in "
                         f"{entry.exposure.lockfile_path}")
        lines.append("")

    items = report.rotation_items
    unnamed = report.unnamed_rotations
    if items or unnamed:
        lines.append(f"rotate ({_rotate_summary(items, report.unnamed_repos)})")
        for item in items:
            scope = "" if item.is_narrowed else f" [{item.scope.value}]"
            runs_cited = f" (run {', '.join(item.run_ids)})" if item.run_ids else ""
            lines += _folded(f"  [{item.grade.value:11s}] {item.repo}: {item.secret}"
                             f"{scope}{runs_cited} — ", item.reason, " " * 16)
        # Printed alongside the named items rather than instead of them. The `elif`
        # that used to stand here dropped this block the moment any *other*
        # repository named a credential, so a repository whose secret listing failed
        # was left out of the rotation section entirely while the headline counted
        # only the credentials that could be named.
        for note in unnamed:
            lines += _folded("  [could not be named] ", note, " " * 16)
    else:
        lines.append("rotate: nothing")

    if report.errors:
        lines += ["", "could not scan (verdict is not complete)"]
        lines += [f"  {e}" for e in report.errors]
    if report.transient:
        lines += ["", "could not run (retrying may help)"]
        lines += [f"  {t}" for t in report.transient]
    if report.incomplete:
        lines += ["", "incomplete view (a deeper clone would say more)"]
        lines += [f"  {i}" for i in report.incomplete]
    if report.unresolved:
        lines += ["", "could not classify (a workflow may install these trees)"]
        for entry in report.unresolved:
            lines += _folded("  ", entry, " " * 4)
    if report.unread:
        lines += ["", "not judged (no lockfile this tool can read)"]
        lines += [f"  {u}" for u in report.unread]
    # The same reasons reach `rotation_notes` for a repo that also rotates; print
    # each once, under the heading that explains it.
    caveats = report.caveats
    if caveats:
        lines.append("")
        lines.append("caveats")
        for caveat in caveats:
            lines += _folded("  ", caveat, " " * 4)
    if not report.proves_absence:
        lines += ["", "this scan cannot prove absence of exposure"]
    return "\n".join(lines)
