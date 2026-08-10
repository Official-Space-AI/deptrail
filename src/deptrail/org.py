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
(measured on this project's own repository — see ``docs/experiments.md``, E7).
Such exposures stay in the report under their own heading with the reason, so a
human can overrule the classification; they simply do not produce rotation items.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

from .grading import Grade, GradedFinding, RunHistory, grade_finding
from .history import Exposure, Verdict, scan_repo
from .ioc import QueryPlan
from .rotation import RepoRotation, RotationItem, rotation_for_repo

RunsProvider = Callable[[Path, str], RunHistory]
SecretsProvider = Callable[[Path, str], tuple[str, ...]]

# Directory names whose lockfiles are test data or documentation rather than a
# tree any workflow installs.
NON_DEPLOYED_DIRS = frozenset({
    "test", "tests", "spec", "specs", "fixture", "fixtures", "__fixtures__",
    "testdata", "example", "examples", "sample", "samples", "demo", "demos",
    "node_modules", "vendor",
})


def is_probably_installed(lockfile_path: str) -> bool:
    """Whether a workflow would plausibly install this lockfile.

    A root lockfile, or one in a workspace directory, is installed. One under a
    fixture or example directory is committed data — flagging it would inflate a
    rotation list with credentials nothing ever exposed.
    """
    directories = PurePosixPath(lockfile_path).parts[:-1]
    return not any(part.lower() in NON_DEPLOYED_DIRS for part in directories)


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


@dataclass
class OrgReport:
    """What one advisory did to one organization."""

    advisory_id: str
    advisory_name: str
    findings: list[GradedFinding] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    rotations: list[RepoRotation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    repos_scanned: int = 0
    partial_coverage: bool = False

    @property
    def exposed_repos(self) -> tuple[str, ...]:
        """Repos with an exposure in a tree a workflow would install."""
        return tuple(sorted({e.repo for e in self.timeline if e.probably_installed}))

    @property
    def set_aside(self) -> tuple[TimelineEntry, ...]:
        """Exposures in fixture or example trees, kept visible but not rotated."""
        return tuple(e for e in self.timeline if not e.probably_installed)

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
                widest = (existing.scope if not existing.is_narrowed
                          else item.scope if not item.is_narrowed else item.scope)
                reasons = existing.reason if existing.reason == item.reason else (
                    f"{existing.reason}; {item.reason}"
                )
                merged[key] = replace(
                    stronger, scope=widest, reason=reasons,
                    run_ids=tuple(sorted(set(existing.run_ids) | set(item.run_ids))),
                )
        return tuple(sorted(merged.values(),
                            key=lambda i: (order.get(i.grade, 3), i.repo, i.secret)))

    @property
    def rotation_notes(self) -> tuple[str, ...]:
        """Per-repository caveats, deduplicated, prefixed with the repo they came from."""
        seen, notes = set(), []
        for rotation in self.rotations:
            for note in rotation.notes:
                line = f"{rotation.repo}: {note}"
                if line not in seen:
                    seen.add(line)
                    notes.append(line)
        return tuple(notes)

    @property
    def worst_grade(self) -> Grade:
        for grade in (Grade.CONFIRMED, Grade.LIKELY, Grade.POSSIBLE):
            if any(e.grade is grade for e in self.timeline if e.probably_installed):
                return grade
        return Grade.NO_EVIDENCE

    @property
    def proves_absence(self) -> bool:
        """Whether "nothing found" may be reported as an all-clear.

        False if any repository failed to scan or the advisory only covers part of
        the incident: in both cases something was not looked at.
        """
        readable = all(f.verdict is not Verdict.INDETERMINATE for f in self.findings)
        return not self.errors and not self.partial_coverage and readable


def scan_organization(repos: Iterable[tuple[str, Path]], plan: QueryPlan, *,
                      runs: RunsProvider, secrets: SecretsProvider | None = None,
                      ) -> OrgReport:
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
        for entry in plan.entries:
            query = entry.query
            try:
                finding = scan_repo(path, query)
                history = runs(path, name)
            except Exception as e:  # a failed repo must be visible, not silent
                report.errors.append(f"{name} ({query.package}): {type(e).__name__}: {e}")
                continue
            graded = grade_finding(
                finding, query, history,
                advisory_id=plan.advisory_id, coverage_warning=plan.coverage_warning,
            )
            report.timeline.extend(
                TimelineEntry(
                    repo=name, package=query.package, exposure=g.exposure,
                    grade=g.grade, evidence=g.evidence, run_ids=g.run_ids,
                    probably_installed=is_probably_installed(g.exposure.lockfile_path),
                )
                for g in graded.graded
            )
            kept = [g for g in graded.graded
                    if is_probably_installed(g.exposure.lockfile_path)]
            # The verdict has to be recomputed for the kept set: a repo whose only
            # exposures are fixtures but whose history was unreadable is still
            # INDETERMINATE, and carrying the original EXPOSED verdict here would
            # drop its repo-wide rotation items.
            installed = replace(
                graded, graded=kept,
                verdict=(Verdict.EXPOSED if kept
                         else Verdict.INDETERMINATE if graded.warnings
                         else Verdict.CLEAN),
            )
            # The report keeps the finding the decisions were made on, so its
            # verdict is the one `proves_absence` must answer to.
            report.findings.append(installed)
            if installed.needs_rotation:
                repo_secrets: tuple[str, ...] = ()
                if secrets:
                    try:
                        repo_secrets = secrets(path, name)
                    except Exception as e:
                        # One repo's secret listing failing must not lose the
                        # findings already collected for the rest.
                        report.errors.append(
                            f"{name}: secret names unavailable ({type(e).__name__}: {e})"
                        )
                report.rotations.append(
                    rotation_for_repo(path, name, installed, repo_secrets)
                )

    report.timeline.sort(key=lambda e: (e.exposure.since, e.repo))
    return report


def render_report(report: OrgReport) -> str:
    """A terminal report: the timeline, then the rotation list, then the caveats."""
    lines = [
        f"advisory {report.advisory_id} — {report.advisory_name}",
        f"scanned {report.repos_scanned} repo(s); worst grade {report.worst_grade.value}",
        "",
    ]
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
    if items:
        lines.append(f"rotate ({len(items)} credential(s))")
        for item in items:
            scope = "" if item.is_narrowed else f" [{item.scope.value}]"
            runs_cited = f" (run {', '.join(item.run_ids)})" if item.run_ids else ""
            lines.append(f"  [{item.grade.value:11s}] {item.repo}: {item.secret}"
                         f"{scope}{runs_cited} — {item.reason}")
    else:
        lines.append("rotate: nothing")

    if report.errors:
        lines += ["", "could not scan (verdict is not complete)"]
        lines += [f"  {e}" for e in report.errors]
    caveats = list(report.notes) + list(report.rotation_notes)
    if caveats:
        lines += ["", "caveats"] + [f"  {c}" for c in caveats]
    if not report.proves_absence:
        lines += ["", "this scan cannot prove absence of exposure"]
    return "\n".join(lines)
