"""The `deptrail` command: point it at an advisory and an organization, get a
timeline and a rotation list.

Three entry points, in the order someone meets them:

- ``deptrail demo`` — the whole judgment flow on a mock infection, offline, in
  seconds. No token, no network, no waiting: the first thing to run.
- ``deptrail scan --repo <path>...`` — local clones, with CI evidence only if a
  GitHub token is available. Nothing here needs one.
- ``deptrail scan --org <org>`` — clone (or refresh) every repository in an
  organization and judge them all.

Exit codes are meant for CI: ``0`` nothing to do, ``1`` credentials to rotate,
``2`` the scan could not prove absence (something failed or was unreadable), and
``3`` the input was malformed. A caller must never have to parse prose to learn
that a scan was incomplete.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .demo import advisory_path, build, runs_provider, secrets_provider
from .grading import RunHistory, annotate_installs, runs_from_github
from .ioc import IocError, bundled_feeds, load_advisory
from .org import OrgReport, render_report, scan_organization
from .report import render_html

EXIT_CLEAN = 0
EXIT_ROTATE = 1
EXIT_INCOMPLETE = 2
EXIT_BAD_INPUT = 3


def _exit_code(report: OrgReport) -> int:
    if report.rotation_items or report.rotation_notes:
        return EXIT_ROTATE
    return EXIT_CLEAN if report.proves_absence else EXIT_INCOMPLETE


def _emit(report: OrgReport, args: argparse.Namespace) -> None:
    if args.format == "json":
        print(json.dumps(_as_dict(report), indent=2))
    elif args.format == "html":
        html = render_html(report)
        if args.output:
            Path(args.output).write_text(html)
            print(f"wrote {args.output}", file=sys.stderr)
        else:
            print(html)
    else:
        print(render_report(report))


def _as_dict(report: OrgReport) -> dict:
    """The report as data, for a caller that wants to act on it rather than read it."""
    return {
        "advisory": {"id": report.advisory_id, "name": report.advisory_name},
        "repos_scanned": report.repos_scanned,
        "worst_grade": report.worst_grade.value,
        "proves_absence": report.proves_absence,
        "exposed_repos": list(report.exposed_repos),
        "timeline": [
            {
                "repo": e.repo, "package": e.package, "version": e.exposure.version,
                "lockfile": e.exposure.lockfile_path, "grade": e.grade.value,
                "since": e.exposure.since.isoformat(),
                "until": e.exposure.until.isoformat() if e.exposure.until else None,
                "commit": e.exposure.commit, "chain": list(e.exposure.chain),
                "evidence": list(e.evidence), "run_ids": list(e.run_ids),
                "probably_installed": e.probably_installed,
            }
            for e in report.timeline
        ],
        "rotate": [
            {"repo": i.repo, "secret": i.secret, "scope": i.scope.value,
             "grade": i.grade.value, "reason": i.reason, "run_ids": list(i.run_ids)}
            for i in report.rotation_items
        ],
        "errors": list(report.errors),
        "caveats": list(report.notes) + list(report.rotation_notes),
    }


def _clone_org(org: str, workdir: Path, *, limit: int) -> list[tuple[str, Path]]:
    """Clone or refresh every repository in an organization.

    Clones are full, never shallow: a truncated history cannot answer when a
    version was installed, and the walker would (correctly) refuse to call such a
    repository clean.
    """
    listing = subprocess.run(
        ["gh", "repo", "list", org, "--limit", str(limit), "--json", "name",
         "--jq", ".[].name"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    workdir.mkdir(parents=True, exist_ok=True)
    repos = []
    for name in listing:
        dest = workdir / name
        if (dest / ".git").exists():
            subprocess.run(["git", "-C", str(dest), "fetch", "--quiet", "--all"],
                           check=False, capture_output=True)
        else:
            print(f"cloning {org}/{name}", file=sys.stderr)
            subprocess.run(
                ["git", "clone", "--quiet", f"https://github.com/{org}/{name}.git",
                 str(dest)], check=True, capture_output=True,
            )
        repos.append((name, dest))
    return repos


def _github_runs(org: str, window: tuple[datetime, datetime], *, annotate: bool):
    """CI history for a repository, restricted to the advisory's window."""
    since, until = window

    def provider(path: Path, name: str) -> RunHistory:
        history = runs_from_github(f"{org}/{name}",
                                   since=since - timedelta(days=1),
                                   until=until + timedelta(days=1))
        if annotate:
            history = RunHistory(
                records=annotate_installs(path, history.records),
                oldest_available=history.oldest_available, source=history.source,
            )
        return history
    return provider


def _github_secrets(org: str):
    def provider(path: Path, name: str) -> tuple[str, ...]:
        raw = subprocess.run(
            ["gh", "secret", "list", "--repo", f"{org}/{name}", "--json", "name"],
            check=True, capture_output=True, text=True,
        ).stdout
        return tuple(item["name"] for item in json.loads(raw or "[]"))
    return provider


def _no_runs(path: Path, name: str) -> RunHistory:
    return RunHistory(source="CI evidence not collected (--no-ci)")


def cmd_demo(args: argparse.Namespace) -> int:
    root = Path(args.workdir)
    repos = build(root)
    advisory = load_advisory(advisory_path(root))
    print(f"built {len(repos)} demo repositories in {root}", file=sys.stderr)
    report = scan_organization(repos, advisory.plan(),
                               runs=runs_provider(root), secrets=secrets_provider())
    _emit(report, args)
    return _exit_code(report)


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        advisory = load_advisory(args.ioc)
    except IocError as e:
        print(f"advisory rejected: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.org:
        repos = _clone_org(args.org, Path(args.workdir), limit=args.limit)
    else:
        repos = [(Path(p).name, Path(p)) for p in args.repo]
    if not repos:
        print("nothing to scan: pass --org or one or more --repo paths", file=sys.stderr)
        return EXIT_BAD_INPUT

    runs = _no_runs
    secrets = None
    if args.org and not args.no_ci:
        runs = _github_runs(args.org, advisory.window, annotate=True)
        secrets = _github_secrets(args.org)

    report = scan_organization(repos, advisory.plan(), runs=runs, secrets=secrets)
    _emit(report, args)
    return _exit_code(report)


def cmd_feeds(args: argparse.Namespace) -> int:
    for name in bundled_feeds():
        advisory = load_advisory(name)
        print(f"{name}\t{advisory.id}\t{advisory.name}\t[{advisory.coverage}]")
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deptrail",
        description="Judge which repositories installed a compromised package, "
                    "and which credentials that puts at risk.",
    )
    parser.set_defaults(func=None)
    subs = parser.add_subparsers(dest="command")

    def add_output(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--format", choices=("text", "json", "html"), default="text")
        sub.add_argument("--output", help="write the report to a file instead of stdout")

    demo = subs.add_parser("demo", help="judge a bundled mock infection, offline")
    demo.add_argument("--workdir", default=".deptrail-demo",
                      help="where to build the demo repositories")
    add_output(demo)
    demo.set_defaults(func=cmd_demo)

    scan = subs.add_parser("scan", help="judge real repositories against an advisory")
    scan.add_argument("--ioc", required=True,
                      help="advisory file path, or a bundled feed name")
    scan.add_argument("--org", help="GitHub organization to clone and judge")
    scan.add_argument("--repo", action="append", default=[],
                      help="path to a local clone (repeatable)")
    scan.add_argument("--workdir", default=".deptrail-cache",
                      help="where organization clones are kept")
    scan.add_argument("--limit", type=int, default=200,
                      help="maximum repositories to list from the organization")
    scan.add_argument("--no-ci", action="store_true",
                      help="skip CI and secret lookups (no token needed)")
    add_output(scan)
    scan.set_defaults(func=cmd_scan)

    feeds = subs.add_parser("feeds", help="list bundled advisories")
    feeds.set_defaults(func=cmd_feeds, format="text", output=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.func is None:
        parser.print_help()
        return EXIT_BAD_INPUT
    try:
        return args.func(args)
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip()[:300]
        print(f"a command failed: {' '.join(e.cmd)}\n{detail}", file=sys.stderr)
        return EXIT_INCOMPLETE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
