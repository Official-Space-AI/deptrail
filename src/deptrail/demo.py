"""Build a mock infection an evaluator can judge, offline and in seconds.

The demo has to answer the question the whole tool exists for, without a GitHub
token, without network access, and without waiting: four repositories with real
git history, one of which held a compromised version while the registry served
it, plus the CI run records that decide whether the install actually ran. The
fourth is locked with Yarn, so the demo also shows what the tool says when it
cannot read a project at all — the answer a responder gets most often.

Run records are synthesised rather than fetched, and the advisory ships with the
package. Everything else — the walk, the grading, the rotation scoping — is the
production code path.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

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
    "schema_version": 2,
    "id": "GHSA-demo-0000-0000",
    "name": "Demo incident — chalk compromised",
    "ecosystem": "npm",
    "coverage": "complete",
    "window": {
        "start": WINDOW_START.isoformat(),
        "end": WINDOW_END.isoformat(),
        "provenance": {
            "start": {"kind": "operator-supplied",
                      "source": "https://example.test/demo-advisory"},
            "end": {"kind": "operator-supplied",
                    "source": "https://example.test/demo-advisory"},
        },
    },
    "packages": [{
        "name": "chalk",
        "versions": ["5.6.1"],
        "sources": ["https://example.test/demo-advisory"],
        "notes": "Synthetic advisory for the bundled demo; not a real incident.",
    }],
    "sources": ["https://example.test/demo-advisory"],
    "notes": "Window is the interval the malicious version was installable.",
}


class DemoRepo(NamedTuple):
    """One repository of the mock organization.

    ``states`` are (commit time, chalk version) pairs written to ``lockfile`` in
    order, so a repository's history is described by what it pinned when.
    """

    name: str
    secrets: tuple[str, ...]
    workflows: dict[str, str]
    states: tuple[tuple[str, str], ...]
    lockfile: str = "package-lock.json"


LAYOUT = (
    DemoRepo(
        "api-server",
        ("NPM_TOKEN", "DEPLOY_KEY", "AWS_ACCESS_KEY"),
        {".github/workflows/ci.yml": CI_WORKFLOW},
        (("2025-11-20T10:00:00+00:00", "5.6.0"),
         ("2025-11-25T14:30:00+00:00", "5.6.1"),   # inside the window
         ("2025-11-28T09:00:00+00:00", "5.6.2")),
    ),
    DemoRepo(
        "web-frontend",
        ("VERCEL_TOKEN",),
        {".github/workflows/ci.yml": CI_WORKFLOW},
        (("2025-11-10T11:00:00+00:00", "5.6.0"),
         ("2025-11-29T16:00:00+00:00", "5.6.2")),  # skipped over the window
    ),
    DemoRepo(
        "docs-site",
        ("ALGOLIA_KEY",),
        {".github/workflows/docs.yml": DOCS_WORKFLOW},
        (("2025-11-25T12:00:00+00:00", "5.6.1"),),  # exposed, but CI installs nothing
    ),
    # Locked with Yarn, which this version cannot parse: the demo has to show the
    # answer a responder gets when the tool cannot see, because that answer is
    # neither "clean" nor "rotate everything".
    DemoRepo(
        "mobile-app",
        ("EXPO_TOKEN",),
        {".github/workflows/ci.yml": CI_WORKFLOW},
        (("2025-11-25T09:00:00+00:00", "5.6.1"),),
        lockfile="yarn.lock",
    ),
)


SENTINEL = ".deptrail-demo-repo"


def _git(repo: Path, *args: str, when: str | None = None) -> None:
    env = dict(os.environ)
    if when:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
    # The demo must run identically on a machine with no git identity, and must
    # not pick up a global commit.gpgsign or template that would fail or differ.
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_TERMINAL_PROMPT": "0"})
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=demo@deptrail", "-c",
         "user.name=deptrail demo", "-c", "commit.gpgsign=false",
         "-c", "init.defaultBranch=main", *args],
        check=True, capture_output=True, env=env,
    )


def _yarn_lockfile(chalk_version: str) -> str:
    """The same pin, in the format Yarn Classic writes."""
    return (
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
        "# yarn lockfile v1\n\n"
        '"chalk@^5.6.0":\n'
        f'  version "{chalk_version}"\n'
        f'  resolved "https://registry.yarnpkg.com/chalk/-/chalk-{chalk_version}.tgz"\n'
    )


def _lockfile(chalk_version: str) -> str:
    """A synthetic lockfile: chalk enters through express -> debug so the report
    shows a transitive chain. The real express does not depend on chalk."""
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
    for spec in LAYOUT:
        repo = root / spec.name
        if repo.exists():
            # Only a directory this command created may be replaced: someone
            # running `deptrail demo --workdir .` in a real workspace must not
            # lose their own api-server.
            if not (repo / SENTINEL).exists():
                raise FileExistsError(
                    f"{repo} already exists and was not created by deptrail demo; "
                    "choose an empty --workdir"
                )
            shutil.rmtree(repo)
        repo.mkdir()
        (repo / SENTINEL).write_text("created by `deptrail demo`\n")
        _git(repo, "init", "-q")
        for path, body in spec.workflows.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        write = _yarn_lockfile if spec.lockfile == "yarn.lock" else _lockfile
        for when, version in spec.states:
            (repo / spec.lockfile).write_text(write(version))
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", f"chore: chalk {version}", when=when)
        repos.append((spec.name, repo))
    return repos


def advisory_path(root: Path) -> Path:
    """Write the demo advisory next to the repos so it can be inspected."""
    path = root / "demo-advisory.json"
    path.write_text(json.dumps(ADVISORY, indent=2) + "\n")
    return path


def _commit_pinning(repo: Path, version: str) -> str:
    """The commit whose lockfile pins ``version``, found by reading the snapshots."""
    shas = subprocess.run(
        ["git", "-C", str(repo), "log", "--format=%H", "--", "package-lock.json"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    for sha in shas:
        body = subprocess.run(
            ["git", "-C", str(repo), "show", f"{sha}:package-lock.json"],
            check=True, capture_output=True, text=True,
        ).stdout
        if f'"version": "{version}"' in body:
            return sha
    raise LookupError(f"no commit in {repo} pins {version}")


def runs_provider(root: Path):
    """Synthetic CI history: api-server and docs-site built during the window.

    api-server's workflow installs dependencies, docs-site's does not — the two
    grades a responder must be able to tell apart.
    """
    def provider(path: Path, name: str) -> RunHistory:
        records: list[RunRecord] = []
        if name == "api-server":
            # The run that built the exposing commit, an hour after it landed. The
            # commit is found by its content, so adding a state to LAYOUT cannot
            # silently point the run at the wrong tree.
            records.append(RunRecord(
                run_id="4412", head_sha=_commit_pinning(path, "5.6.1"),
                started_at=datetime(2025, 11, 25, 15, 30, tzinfo=timezone.utc),
                workflow="CI", event="push",
                workflow_path=".github/workflows/ci.yml",
            ))
        if name == "docs-site":
            records.append(RunRecord(
                run_id="4415", head_sha=_commit_pinning(path, "5.6.1"),
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
    holdings = {spec.name: spec.secrets for spec in LAYOUT}

    def provider(path: Path, name: str) -> tuple[str, ...]:
        return holdings.get(name, ())
    return provider
