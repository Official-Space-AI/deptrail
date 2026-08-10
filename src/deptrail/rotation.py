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
from .history import GitError, _git as _git_text

# ``${{ secrets.NAME }}`` in any of its spacings, plus the wildcard form that
# hands a called workflow everything the caller can see.
SECRET_REFERENCE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_-]*)")
SECRETS_INHERIT = re.compile(r"secrets:\s*inherit")


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


def secrets_in_workflow(repo: Path, sha: str, workflow_path: str | None,
                        ) -> tuple[tuple[str, ...], Scope, str]:
    """Secrets the workflow at ``sha`` could reach, and how firmly we know it.

    Returns the names, the scope they justify, and a one-line reason for the
    report. A workflow we cannot attribute or read never narrows the list.
    """
    if workflow_path is None:
        return (), Scope.REPO_WIDE, "the run's workflow file is unknown"
    try:
        body = _git_text(repo, "show", f"{sha}:{workflow_path}")
    except GitError:
        return (), Scope.REPO_WIDE, f"{workflow_path} could not be read at {sha[:8]}"
    if SECRETS_INHERIT.search(body):
        return (), Scope.REPO_WIDE, f"{workflow_path} passes `secrets: inherit`"
    names = tuple(sorted(set(SECRET_REFERENCE.findall(body))))
    if not names:
        return (), Scope.WORKFLOW, f"{workflow_path} references no secrets"
    return names, Scope.WORKFLOW, f"named in {workflow_path} at {sha[:8]}"


def rotation_for_repo(repo_path: Path, repo_name: str, finding: GradedFinding,
                      repo_secrets: tuple[str, ...] = (),
                      ) -> RepoRotation:
    """Build one repository's rotation list from its graded exposures."""
    rotation = RepoRotation(repo=repo_name)
    if finding.coverage_warning:
        rotation.notes.append(finding.coverage_warning)
    for warning in finding.warnings:
        rotation.notes.append(warning)

    graded_needing = [g for g in finding.graded
                      if g.grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE)]
    if not graded_needing:
        if finding.needs_rotation:
            # No exposure was found, yet the verdict is not clean: the history
            # itself was unreadable, so nothing can be narrowed or cleared.
            rotation.items.extend(
                RotationItem(repo=repo_name, secret=secret, scope=Scope.REPO_WIDE,
                             grade=Grade.POSSIBLE,
                             reason="this repository's history could not be read, "
                                    "so exposure was neither shown nor ruled out")
                for secret in repo_secrets or ("(secret names unavailable)",)
            )
        return rotation

    for item in graded_needing:
        rotation.items.extend(
            _items_for_exposure(repo_path, repo_name, item, repo_secrets)
        )
    return rotation


def _items_for_exposure(repo_path: Path, repo_name: str, graded: GradedExposure,
                        repo_secrets: tuple[str, ...]) -> list[RotationItem]:
    exposure = graded.exposure
    if not graded.run_ids:
        return [
            RotationItem(
                repo=repo_name, secret=secret, scope=Scope.DEVELOPER,
                grade=graded.grade,
                reason=f"{exposure.version} was pinned in {exposure.lockfile_path} "
                       "with no CI run implicated; whoever installed it locally "
                       "held these credentials",
            )
            for secret in repo_secrets or ("(secret names unavailable)",)
        ]

    names, scope, why = secrets_in_workflow(
        repo_path, exposure.commit, _workflow_path_of(graded)
    )
    if scope is Scope.WORKFLOW and names:
        return [
            RotationItem(repo=repo_name, secret=secret, scope=scope,
                         grade=graded.grade, reason=why, run_ids=graded.run_ids)
            for secret in names
        ]
    if scope is Scope.WORKFLOW:
        # The implicated workflow reads no secrets at all; nothing to rotate from
        # this exposure, but the finding still stands and is reported as a note.
        return []
    return [
        RotationItem(repo=repo_name, secret=secret, scope=Scope.REPO_WIDE,
                     grade=graded.grade, reason=why, run_ids=graded.run_ids)
        for secret in repo_secrets or ("(secret names unavailable)",)
    ]


def _workflow_path_of(graded: GradedExposure) -> str | None:
    """The workflow file behind a grade, if the grader recorded one."""
    return graded.workflow_path
