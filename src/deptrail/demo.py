"""Build a mock infection an evaluator can judge, offline and in seconds.

The demo has to answer the question the whole tool exists for, without a GitHub
token, without network access, and without waiting: three repositories with real
git history, one of which held a compromised version while the registry served
it, plus the CI run records that decide whether the install actually ran.

Run records are synthesised rather than fetched, and the advisory ships with the
package. Everything else — the walk, the grading, the rotation scoping — is the
production code path.
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .grading import RunHistory, RunRecord, annotate_installs

WINDOW_START = datetime(2025, 11, 24, tzinfo=timezone.utc)
WINDOW_END = datetime(2025, 11, 26, 23, 59, 59, tzinfo=timezone.utc)

CI_WORKFLOW = """\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - name: Publish preview
        run: ./deploy.sh
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
"""

DOCS_WORKFLOW = """\
name: Docs
on: [push]
jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make docs
"""

ADVISORY = {
    "schema_version": 1,
    "id": "GHSA-demo-0000-0000",
    "name": "Demo incident — chalk compromised",
    "ecosystem": "npm",
    "coverage": "complete",
    "window": {"start": WINDOW_START.isoformat(), "end": WINDOW_END.isoformat()},
    "packages": [{
        "name": "chalk",
        "versions": ["5.6.1"],
        "sources": ["https://example.test/demo-advisory"],
        "notes": "Synthetic advisory for the bundled demo; not a real incident.",
    }],
    "sources": ["https://example.test/demo-advisory"],
    "notes": "Window is the interval the malicious version was installable.",
}

# (repo, secrets it holds, workflows, lockfile states as (commit time, chalk version))
LAYOUT = (
    (
        "api-server",
        ("NPM_TOKEN", "DEPLOY_KEY", "AWS_ACCESS_KEY"),
        {".github/workflows/ci.yml": CI_WORKFLOW},
        (("2025-11-20T10:00:00+00:00", "5.6.0"),
         ("2025-11-25T14:30:00+00:00", "5.6.1"),   # inside the window
         ("2025-11-28T09:00:00+00:00", "5.6.2")),
    ),
    (
        "web-frontend",
        ("VERCEL_TOKEN",),
        {".github/workflows/ci.yml": CI_WORKFLOW},
        (("2025-11-10T11:00:00+00:00", "5.6.0"),
         ("2025-11-29T16:00:00+00:00", "5.6.2")),  # skipped over the window
    ),
    (
        "docs-site",
        ("ALGOLIA_KEY",),
        {".github/workflows/docs.yml": DOCS_WORKFLOW},
        (("2025-11-25T12:00:00+00:00", "5.6.1"),),  # exposed, but CI installs nothing
    ),
)


def _git(repo: Path, *args: str, when: str | None = None) -> None:
    env = dict(os.environ)
    if when:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=demo@deptrail", "-c",
         "user.name=deptrail demo", *args],
        check=True, capture_output=True, env=env,
    )


def _lockfile(chalk_version: str) -> str:
    """A lockfile where chalk arrives through express -> debug, as in the real wave."""
    return json.dumps({
        "name": "app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "^4.19.0"}},
            "node_modules/express": {"version": "4.19.2",
                                     "dependencies": {"debug": "^4.3.4"}},
            "node_modules/debug": {"version": "4.3.5",
                                   "dependencies": {"chalk": "^5.6.0"}},
            "node_modules/chalk": {"version": chalk_version},
        },
    }, indent=2)


def build(root: Path) -> list[tuple[str, Path]]:
    """Create the demo organization on disk and return its (name, path) pairs."""
    root.mkdir(parents=True, exist_ok=True)
    repos = []
    for name, _, workflows, states in LAYOUT:
        repo = root / name
        if repo.exists():
            subprocess.run(["rm", "-rf", str(repo)], check=True)
        repo.mkdir()
        _git(repo, "init", "-q")
        for path, body in workflows.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        for when, version in states:
            (repo / "package-lock.json").write_text(_lockfile(version))
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", f"chore: chalk {version}", when=when)
        repos.append((name, repo))
    return repos


def advisory_path(root: Path) -> Path:
    """Write the demo advisory next to the repos so it can be inspected."""
    path = root / "demo-advisory.json"
    path.write_text(json.dumps(ADVISORY, indent=2) + "\n")
    return path


def runs_provider(root: Path):
    """Synthetic CI history: api-server and docs-site built during the window.

    api-server's workflow installs dependencies, docs-site's does not — the two
    grades a responder must be able to tell apart.
    """
    def provider(path: Path, name: str) -> RunHistory:
        head = subprocess.run(
            ["git", "-C", str(path), "log", "--format=%H", "--", "package-lock.json"],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        records: list[RunRecord] = []
        if name == "api-server":
            # The run that built the exposing commit, one hour after it landed.
            exposing = head[1]  # newest first: [5.6.2, 5.6.1, 5.6.0]
            records.append(RunRecord(
                run_id="4412", head_sha=exposing,
                started_at=datetime(2025, 11, 25, 15, 30, tzinfo=timezone.utc),
                workflow="CI", event="push",
                workflow_path=".github/workflows/ci.yml",
            ))
        if name == "docs-site":
            records.append(RunRecord(
                run_id="4415", head_sha=head[0],
                started_at=datetime(2025, 11, 25, 13, 0, tzinfo=timezone.utc),
                workflow="Docs", event="push",
                workflow_path=".github/workflows/docs.yml",
            ))
        return RunHistory(
            # Install evidence is derived the production way: from the workflow
            # files committed at each run's own commit.
            records=annotate_installs(path, tuple(records)),
            oldest_available=WINDOW_START - timedelta(days=30),
            source="bundled demo run records",
        )
    return provider


def secrets_provider() -> object:
    """Secret names each demo repository holds, as a listing would report them."""
    holdings = {name: secrets for name, secrets, _, _ in LAYOUT}

    def provider(path: Path, name: str) -> tuple[str, ...]:
        return holdings.get(name, ())
    return provider
