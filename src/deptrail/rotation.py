"""Turn graded exposures into the answer a responder actually needs: what to rotate.

The scan's whole purpose is a short, defensible rotation list. Two errors are
possible and they are not symmetric: rotating a credential that was never at risk
costs minutes, while leaving one live in an attacker's hands is the incident
repeating. So the scope is narrowed only where the evidence supports narrowing,
and every item names the reason it is on the list.

Scope is read from the workflow file at the exposing commit — the same file the
grader reads for install evidence — because that file states which secrets that
run could see. Three scopes come out of it:

- ``WORKFLOW``  — a specific run is implicated and its workflow names the secrets
  it can reach, so the list is exactly those.
- ``REPO_WIDE`` — a run is implicated but its scope cannot be narrowed
  (``secrets: inherit``, an unreadable workflow, an unknown workflow path): every
  secret the repository can see is a candidate.
- ``DEVELOPER`` — no run is implicated at all. The install still happened
  somewhere, most likely on the machine of whoever committed the lockfile, so the
  list is the repository's secrets plus a note that local credentials are in
  scope and no log will ever prove it.

Secret *names* are all that is ever read. Values are not accessible through the
API by design, and this tool never asks for them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .grading import Grade, GradedExposure, GradedFinding
from .history import GitError, Verdict, _git as _git_text

# Only ``${{ ... }}`` expressions can read the secrets context, so references are
# looked for inside those blocks: a commented-out secret or the literal string
# "secrets.FOO" in an echo is not an access, and listing it would put a
# credential nobody used on the rotation list.
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
COMMENT = re.compile(r"(?m)(?<!\$)#.*$")
SECRET_REFERENCE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_-]*)")
# Local reusable workflows are followed: the caller often names no secrets while
# the callee reads them.
LOCAL_USES = re.compile(r"uses:\s*[\"']?(\./[^\s\"']+\.ya?ml)")
# Environment secrets resolve through the same ``secrets.NAME`` syntax but are not
# returned by a repository secret listing, so an environment has to be named in
# the report or its credentials would silently miss the REPO_WIDE fallback.
ENVIRONMENT = re.compile(r"(?m)^\s*environment:\s*[\"']?([A-Za-z0-9._-]+)")
REMOTE_USES = re.compile(r"uses:\s*[\"']?([A-Za-z0-9._-]+/[A-Za-z0-9._-]+/\.github/workflows/[^\s\"']+)")
# Forms that hand a job every secret it could see, so nothing can be narrowed:
# passing them on to a called workflow, serialising the whole context, or
# selecting a name at runtime.
WILDCARDS = (
    (re.compile(r"secrets:\s*inherit"), "passes `secrets: inherit`"),
    (re.compile(r"toJSON\(\s*secrets\s*\)"), "serialises the whole `secrets` context"),
    (re.compile(r"secrets\s*\["), "selects a secret name at runtime (`secrets[...]`)"),
)
# Rotating GITHUB_TOKEN is not a thing a responder can do: it is minted per run
# and expires when the run ends. It is reported as context, never as an action.
EPHEMERAL_SECRETS = frozenset({"GITHUB_TOKEN"})


class Scope(str, Enum):
    WORKFLOW = "WORKFLOW"
    REPO_WIDE = "REPO_WIDE"
    DEVELOPER = "DEVELOPER"


@dataclass(frozen=True)
class RotationItem:
    """One credential to rotate, with the evidence that put it on the list."""

    repo: str
    secret: str
    scope: Scope
    grade: Grade
    reason: str
    run_ids: tuple[str, ...] = ()

    @property
    def is_narrowed(self) -> bool:
        return self.scope is Scope.WORKFLOW


@dataclass
class RepoRotation:
    """Rotation items for one repository, plus what limited the scoping."""

    repo: str
    items: list[RotationItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _expressions(body: str) -> str:
    """The text of every ``${{ ... }}`` block, comments stripped first."""
    return " ".join(EXPRESSION.findall(COMMENT.sub("", body)))


def secrets_in_workflow(repo: Path, sha: str, workflow_path: str | None,
                        _seen: frozenset[str] = frozenset(),
                        ) -> tuple[tuple[str, ...], Scope, str]:
    """Secrets one workflow at ``sha`` could reach, and how firmly we know it.

    Returns the names, the scope they justify, and a one-line reason for the
    report. A workflow we cannot attribute or read never narrows the list, and
    neither does one that can reach secrets it does not name. Local reusable
    workflows it calls are followed, because the caller often names nothing while
    the callee reads the deploy token.
    """
    if workflow_path is None:
        return (), Scope.REPO_WIDE, "the run's workflow file is unknown"
    if workflow_path in _seen:  # a cycle in reusable workflow calls
        return (), Scope.WORKFLOW, f"{workflow_path} already accounted for"
    try:
        body = _git_text(repo, "show", f"{sha}:{workflow_path}")
    except GitError:
        return (), Scope.REPO_WIDE, f"{workflow_path} could not be read at {sha[:8]}"
    for pattern, description in WILDCARDS:
        if pattern.search(COMMENT.sub("", body)):
            return (), Scope.REPO_WIDE, f"{workflow_path} {description}"

    names = set(SECRET_REFERENCE.findall(_expressions(body)))
    reasons = [f"named in {workflow_path} at {sha[:8]}"] if names else []
    seen = _seen | {workflow_path}

    for called in LOCAL_USES.findall(COMMENT.sub("", body)):
        target = called[2:] if called.startswith("./") else called
        found, scope, why = secrets_in_workflow(repo, sha, target, seen)
        if scope is Scope.REPO_WIDE:
            return (), Scope.REPO_WIDE, f"{workflow_path} calls {target}: {why}"
        names.update(found)
        if found:
            reasons.append(why)
    if REMOTE_USES.search(COMMENT.sub("", body)):
        return (), Scope.REPO_WIDE, (
            f"{workflow_path} calls a reusable workflow in another repository, "
            "whose secret use cannot be read here"
        )

    if not names:
        return (), Scope.WORKFLOW, f"{workflow_path} references no secrets"
    return tuple(sorted(names)), Scope.WORKFLOW, "; ".join(reasons)


def secrets_across_workflows(repo: Path, sha: str, paths: tuple[str, ...],
                             ) -> tuple[tuple[str, ...], Scope, str]:
    """Union the secrets of every implicated workflow.

    One push fires several workflows and each one's environment held its own
    secrets, so narrowing to the first file would silently drop the rest. If any
    of them cannot be narrowed, the whole exposure cannot be.
    """
    if not paths:
        return (), Scope.REPO_WIDE, "no workflow file could be attributed to the run"
    names: set[str] = set()
    reasons = []
    for path in paths:
        found, scope, why = secrets_in_workflow(repo, sha, path)
        if scope is Scope.REPO_WIDE:
            return (), Scope.REPO_WIDE, why
        names.update(found)
        reasons.append(why)
    if not names:
        return (), Scope.WORKFLOW, "; ".join(reasons)
    return tuple(sorted(names)), Scope.WORKFLOW, "; ".join(reasons)


def environments_in_workflows(repo: Path, sha: str, paths: tuple[str, ...],
                              ) -> tuple[str, ...]:
    """GitHub environments the implicated workflows enter at that commit."""
    found: set[str] = set()
    for path in paths:
        try:
            body = COMMENT.sub("", _git_text(repo, "show", f"{sha}:{path}"))
        except GitError:
            continue
        found.update(ENVIRONMENT.findall(body))
    return tuple(sorted(found))


def rotation_for_repo(repo_path: Path, repo_name: str, finding: GradedFinding,
                      repo_secrets: tuple[str, ...] | None = None,
                      ) -> RepoRotation:
    """Build one repository's rotation list from its graded exposures."""
    rotation = RepoRotation(repo=repo_name)
    if finding.coverage_warning:
        rotation.notes.append(finding.coverage_warning)
    for warning in (*finding.warnings, *finding.ci_notes):
        rotation.notes.append(warning)

    graded_needing = [g for g in finding.graded
                      if g.grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE)]
    if finding.verdict is Verdict.INDETERMINATE:
        # The history itself was unreadable, so nothing can be narrowed or
        # cleared — independent of whatever exposures were found elsewhere.
        rotation.items.extend(_repo_wide_items(
            repo_name, repo_secrets, Grade.POSSIBLE, rotation,
            "this repository's history could not be read, so exposure was "
            "neither shown nor ruled out",
        ))

    for item in graded_needing:
        rotation.items.extend(
            _items_for_exposure(repo_path, repo_name, item, repo_secrets, rotation)
        )
    return rotation


def _repo_wide_items(repo_name: str, repo_secrets: tuple[str, ...] | None, grade: Grade,
                     rotation: RepoRotation, reason: str,
                     run_ids: tuple[str, ...] = ()) -> list[RotationItem]:
    """Items covering every secret the repo can see, or a note if we cannot list them.

    A placeholder entry would be counted and read as a credential; saying plainly
    that the names are unavailable — or that there are none — is the honest
    alternative. ``None`` means the listing failed, ``()`` means it returned empty.
    """
    if repo_secrets is None:
        rotation.notes.append(
            f"{reason} — and this repository's secret names could not be listed, "
            "so rotate everything it can see"
        )
        return []
    if not repo_secrets:
        rotation.notes.append(f"{reason} — this repository holds no secrets")
        return []
    return [
        RotationItem(repo=repo_name, secret=secret, scope=Scope.REPO_WIDE,
                     grade=grade, reason=reason, run_ids=run_ids)
        for secret in repo_secrets if secret not in EPHEMERAL_SECRETS
    ]


def _items_for_exposure(repo_path: Path, repo_name: str, graded: GradedExposure,
                        repo_secrets: tuple[str, ...] | None,
                        rotation: RepoRotation) -> list[RotationItem]:
    exposure = graded.exposure
    if not graded.run_ids or not graded.implicates_install:
        why_local = ("no CI run implicated" if not graded.run_ids else
                     "the implicated run(s) could not have installed it")
        reason = (f"{exposure.version} was pinned in {exposure.lockfile_path} with "
                  f"{why_local}, so the install happened outside CI; Actions "
                  "secrets are not automatically present on a developer machine, "
                  "but the same values often are — investigate that machine's "
                  "credentials as well")
        if repo_secrets is None:
            rotation.notes.append(
                f"{reason} — and this repository's secret names could not be listed"
            )
            return []
        if not repo_secrets:
            rotation.notes.append(f"{reason} — this repository holds no secrets")
            return []
        return [
            RotationItem(repo=repo_name, secret=secret, scope=Scope.DEVELOPER,
                         grade=graded.grade, reason=reason)
            for secret in repo_secrets if secret not in EPHEMERAL_SECRETS
        ]

    environments = environments_in_workflows(
        repo_path, exposure.commit, graded.workflow_paths
    )
    if environments:
        rotation.notes.append(
            f"the implicated run(s) entered environment(s) "
            f"{', '.join(environments)}; secrets defined on an environment are not "
            "in a repository secret listing, so check them separately"
        )
    names, scope, why = secrets_across_workflows(
        repo_path, exposure.commit, graded.workflow_paths
    )
    if scope is Scope.WORKFLOW and names:
        actionable = [n for n in names if n not in EPHEMERAL_SECRETS]
        skipped = sorted(set(names) - set(actionable))
        if skipped:
            rotation.notes.append(
                f"{', '.join(skipped)} was in scope but expires with its run, so it "
                "is not on the rotation list"
            )
        return [
            RotationItem(repo=repo_name, secret=secret, scope=scope,
                         grade=graded.grade, reason=why, run_ids=graded.run_ids)
            for secret in actionable
        ]
    if scope is Scope.WORKFLOW:
        rotation.notes.append(
            f"{exposure.version} ran in {repo_name} but {why}, so no credential "
            "from this exposure needs rotating"
        )
        return []
    return _repo_wide_items(repo_name, repo_secrets, graded.grade, rotation, why,
                            graded.run_ids)
