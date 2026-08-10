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

# ``${{ secrets.NAME }}`` in any of its spacings.
SECRET_REFERENCE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_-]*)")
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


def secrets_in_workflow(repo: Path, sha: str, workflow_path: str | None,
                        ) -> tuple[tuple[str, ...], Scope, str]:
    """Secrets one workflow at ``sha`` could reach, and how firmly we know it.

    Returns the names, the scope they justify, and a one-line reason for the
    report. A workflow we cannot attribute or read never narrows the list, and
    neither does one that can reach secrets it does not name.
    """
    if workflow_path is None:
        return (), Scope.REPO_WIDE, "the run's workflow file is unknown"
    try:
        body = _git_text(repo, "show", f"{sha}:{workflow_path}")
    except GitError:
        return (), Scope.REPO_WIDE, f"{workflow_path} could not be read at {sha[:8]}"
    for pattern, description in WILDCARDS:
        if pattern.search(body):
            return (), Scope.REPO_WIDE, f"{workflow_path} {description}"
    names = tuple(sorted(set(SECRET_REFERENCE.findall(body))))
    if not names:
        return (), Scope.WORKFLOW, f"{workflow_path} references no secrets"
    return names, Scope.WORKFLOW, f"named in {workflow_path} at {sha[:8]}"


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


def _repo_wide_items(repo_name: str, repo_secrets: tuple[str, ...], grade: Grade,
                     rotation: RepoRotation, reason: str,
                     run_ids: tuple[str, ...] = ()) -> list[RotationItem]:
    """Items covering every secret the repo can see, or a note if we cannot list them.

    A placeholder entry would be counted and read as a credential; saying plainly
    that the names are unavailable is the honest alternative.
    """
    if not repo_secrets:
        rotation.notes.append(
            f"{reason} — and this repository's secret names could not be listed, "
            "so rotate everything it can see"
        )
        return []
    return [
        RotationItem(repo=repo_name, secret=secret, scope=Scope.REPO_WIDE,
                     grade=grade, reason=reason, run_ids=run_ids)
        for secret in repo_secrets if secret not in EPHEMERAL_SECRETS
    ]


def _items_for_exposure(repo_path: Path, repo_name: str, graded: GradedExposure,
                        repo_secrets: tuple[str, ...],
                        rotation: RepoRotation) -> list[RotationItem]:
    exposure = graded.exposure
    if not graded.run_ids:
        reason = (f"{exposure.version} was pinned in {exposure.lockfile_path} with "
                  "no CI run implicated; whoever installed it locally held these "
                  "credentials")
        if not repo_secrets:
            rotation.notes.append(
                f"{reason} — and this repository's secret names could not be listed"
            )
            return []
        return [
            RotationItem(repo=repo_name, secret=secret, scope=Scope.DEVELOPER,
                         grade=graded.grade, reason=reason)
            for secret in repo_secrets if secret not in EPHEMERAL_SECRETS
        ]

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
