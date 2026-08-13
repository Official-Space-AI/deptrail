"""The `deptrail` command: point it at an advisory and an organization, get a
timeline and a rotation list.

Three entry points, in the order someone meets them:

- ``deptrail demo`` — the whole judgment flow on a mock infection, offline, in
  seconds. No token, no network, no waiting: the first thing to run.
- ``deptrail scan --repo <path>`` — local clones. CI evidence needs a repository
  to ask about, so pass ``--slug owner/name`` to collect it; without a slug the
  report says so rather than implying the runs were checked.
- ``deptrail scan --org <org>`` — clone (or refresh) every repository in an
  organization and judge them all.

Exit codes are the contract, and a caller must never have to parse prose to learn
what happened. ``0`` and ``1`` are verdicts about evidence that was read; the rest
say no verdict was reached, and they are kept apart because the next move differs:

- ``0`` — absence of exposure was established
- ``1`` — credentials to rotate
- ``2`` — looked, and could not prove absence: a truncated clone, an unreadable
  snapshot, a lockfile dialect this version cannot parse
- ``3`` — the request was malformed: unknown feed, bad advisory, both targets
- ``4`` — the tool could not run: an absent ``git``/``gh``, a failed call, a
  directory it could not write. Retrying may help; for ``2`` it will not.

Every path returns one of these — a traceback escaping as exit 1 would read as
"rotate now".
"""
from __future__ import annotations

import argparse
import errno
import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .demo import advisory_path, build, runs_provider, secrets_provider
from .grading import RunHistory, annotate_installs, runs_from_github
from .ioc import (
    Advisory,
    IocError,
    advisory_template,
    bundled_feeds,
    load_advisory,
    parse_advisory,
)
from .org import OrgReport, render_report, scan_organization
from .report import render_html

# Codes 0 and 1 are verdicts about evidence that was read; everything above says
# the tool did not reach a verdict. The split follows what shipped scanners do —
# OSV-Scanner puts "no packages found" at 128, outside its result range entirely,
# and reserves another range for failures that are nobody's fault but the tool's;
# Snyk keeps "insufficient evidence" and "could not run" on separate codes. Folding
# them together tells a caller to retry when retrying cannot help, or the reverse.
EXIT_CLEAN = 0        # absence of exposure was established
EXIT_ROTATE = 1       # credentials to rotate
EXIT_INCOMPLETE = 2   # looked, and could not prove absence
EXIT_BAD_INPUT = 3    # the request was malformed; fixing it is the caller's move
EXIT_TRANSIENT = 4    # the tool could not run; retrying may help


class Parser(argparse.ArgumentParser):
    """Argparse exits 2 on a usage error, which is this tool's "incomplete scan"."""

    def error(self, message: str):  # pragma: no cover - argparse plumbing
        self.print_usage(sys.stderr)
        print(f"{self.prog}: {message}", file=sys.stderr)
        raise SystemExit(EXIT_BAD_INPUT)


def _exit_code(report: OrgReport, items=None) -> int:
    """One code per outcome, with no overlap.

    Rotation wins over everything: a responder who has credentials to rotate must
    act, and the report states separately what else went wrong. After that, a tool
    that could not run outranks a history that could not be cleared — one is worth
    retrying and the other is not, and folding them together let a failed API call
    leave as exit 2, which the Action then passes off as a warning (#20).

    ``items`` lets a caller that already merged the rotation list pass it in rather
    than pay for the merge again.
    """
    if report.requires_rotation(items):
        return EXIT_ROTATE
    if report.transient:
        return EXIT_TRANSIENT
    return EXIT_CLEAN if report.proves_absence else EXIT_INCOMPLETE


# Errors that say the path itself cannot work. Retrying will not help, so they are the
# caller's to fix; everything else (a full disk, a read-only mount, an I/O fault) is the
# environment and belongs on the retryable code.
_PATH_IS_WRONG = frozenset({
    errno.ENOENT, errno.EISDIR, errno.ENOTDIR, errno.ENAMETOOLONG, errno.EEXIST,
})


def _write_failure(target: str, error: OSError) -> int:
    print(f"could not write {target}: {error}", file=sys.stderr)
    return EXIT_BAD_INPUT if error.errno in _PATH_IS_WRONG else EXIT_TRANSIENT


def _emit(report: OrgReport, args: argparse.Namespace, advisory: Advisory | None) -> int:
    """Write the report where it was asked for. A write failure is not a verdict."""
    if args.format == "json":
        text = json.dumps(_as_dict(report, advisory), indent=2)
    elif args.format == "html":
        text = render_html(report, advisory)
    else:
        text = render_report(report)
    if not args.output:
        print(text)
        return EXIT_CLEAN
    try:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    except OSError as e:
        return _write_failure(args.output, e)
    print(f"wrote {args.output}", file=sys.stderr)
    return EXIT_CLEAN


def _as_dict(report: OrgReport, advisory: Advisory | None) -> dict:
    """The report as data: the decision first, then the evidence behind it.

    ``rotation_items`` is derived once and threaded through. It is a merge that is
    quadratic in the items, and this function used to reach it three times — once
    through ``_exit_code``, once through ``rotation_required``, once for the
    ``rotate`` list — which made the JSON output three times the cost of the text
    one on the same report.
    """
    items = report.rotation_items
    rotation_required = report.requires_rotation(items)
    payload = {
        "decision": {
            "exit_code": _exit_code(report, items=items),
            "rotation_required": rotation_required,
            "scan_complete": report.proves_absence,
            "worst_grade": report.worst_grade.value,
        },
        "advisory": {"id": report.advisory_id, "name": report.advisory_name},
        "repos_scanned": report.repos_scanned,
        "exposed_repos": list(report.exposed_repos),
        "timeline": [
            {
                "repo": e.repo, "package": e.package, "version": e.exposure.version,
                "lockfile": e.exposure.lockfile_path, "grade": e.grade.value,
                "since": e.exposure.since.isoformat(),
                "until": e.exposure.until.isoformat() if e.exposure.until else None,
                "commit": e.exposure.commit, "chain": list(e.exposure.chain),
                "evidence": list(e.evidence), "run_ids": list(e.run_ids),
            }
            for e in report.timeline if e.probably_installed
        ],
        "set_aside": [
            {"repo": e.repo, "package": e.package, "version": e.exposure.version,
             "lockfile": e.exposure.lockfile_path, "grade": e.grade.value}
            for e in report.set_aside
        ],
        "rotate": [
            {"repo": i.repo, "secret": i.secret, "scope": i.scope.value,
             "grade": i.grade.value, "reason": i.reason, "run_ids": list(i.run_ids)}
            for i in items
        ],
        "rotate_unnamed": list(report.unnamed_rotations),
        "errors": list(report.errors),
        "could_not_run": list(report.transient),
        "incomplete_view": list(report.incomplete),
        "not_judged": list(report.unread),
        # The dedicated keys above already carry these lines; repeating them here made
        # a JSON consumer count every gap twice while the text and HTML reports showed
        # it once. The subtraction lives on the report so all three renderers do it
        # the same way.
        "caveats": list(report.caveats),
    }
    if advisory is not None:
        payload["advisory"].update({
            "window": {"start": advisory.window[0].isoformat(),
                       "end": advisory.window[1].isoformat()},
            "coverage": advisory.coverage,
            "sources": list(advisory.sources),
            "packages": [{"name": p.name, "versions": list(p.versions)}
                         for p in advisory.packages],
        })
    return payload


def _expected_remote(org: str, name: str) -> tuple[str, ...]:
    base = f"github.com/{org}/{name}"
    return (f"https://{base}.git", f"https://{base}", f"git@github.com:{org}/{name}.git")


def _clone_org(org: str, workdir: Path, *, limit: int,
               ) -> tuple[list[tuple[str, Path]], list[str], list[str]]:
    """Clone or refresh every repository in an organization.

    Clones are full, never shallow: a truncated history cannot answer when a
    version was installed. Each repository is kept under its own organization
    directory and its remote is verified, so two organizations that share a
    repository name cannot be judged with each other's history. Anything that
    A truncated listing is an error the caller must fix; a clone or fetch that failed
    is the tooling not answering, and is reported as such so the exit code says
    "retry" rather than "we looked". Anything that
    fails becomes something the report must carry — a repository nobody looked at
    may not read as clean.
    """
    errors: list[str] = []
    transient: list[str] = []
    listing = subprocess.run(
        ["gh", "repo", "list", org, "--limit", str(limit), "--json", "name",
         "--jq", ".[].name"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    if len(listing) >= limit:
        errors.append(
            f"{org}: repository list hit the --limit of {limit}; repositories beyond "
            "it were not scanned (raise --limit)"
        )
    root = workdir / org
    root.mkdir(parents=True, exist_ok=True)
    repos = []
    for name in listing:
        dest = root / name
        if (dest / ".git").exists():
            remote = subprocess.run(
                ["git", "-C", str(dest), "remote", "get-url", "origin"],
                capture_output=True, text=True,
            ).stdout.strip()
            if remote and not remote.rstrip("/").startswith(_expected_remote(org, name)):
                errors.append(
                    f"{name}: cached clone at {dest} points at {remote}, not {org}/{name}"
                )
                continue
            fetch = subprocess.run(["git", "-C", str(dest), "fetch", "--prune", "--quiet"],
                                   capture_output=True, text=True)
            if fetch.returncode != 0:
                transient.append(
                    f"{name}: fetch failed, the cached history may be stale "
                    f"({fetch.stderr.strip()[:120]})"
                )
        else:
            print(f"cloning {org}/{name}", file=sys.stderr)
            clone = subprocess.run(
                ["git", "clone", "--quiet", f"https://github.com/{org}/{name}.git",
                 str(dest)], capture_output=True, text=True,
            )
            if clone.returncode != 0:
                transient.append(f"{name}: clone failed ({clone.stderr.strip()[:120]})")
                continue
        repos.append((name, dest))
    return repos, errors, transient


def _github_runs(slug_of, window: tuple[datetime, datetime], *, annotate: bool):
    """CI history for a repository, restricted to the advisory's window."""
    since, until = window

    def provider(path: Path, name: str) -> RunHistory:
        history = runs_from_github(slug_of(name),
                                   since=since - timedelta(days=1),
                                   until=until + timedelta(days=1))
        if annotate:
            history = RunHistory(
                records=annotate_installs(path, history.records),
                oldest_available=history.oldest_available, source=history.source,
            )
        return history
    return provider


def _github_secrets(slug_of):
    def provider(path: Path, name: str) -> tuple[str, ...]:
        raw = subprocess.run(
            ["gh", "secret", "list", "--repo", slug_of(name), "--json", "name"],
            check=True, capture_output=True, text=True,
        ).stdout
        return tuple(item["name"] for item in json.loads(raw or "[]"))
    return provider


def _uncollected_runs(reason: str):
    def provider(path: Path, name: str) -> RunHistory:
        return RunHistory(source=reason)
    return provider


def cmd_demo(args: argparse.Namespace) -> int:
    root = Path(args.workdir)
    try:
        repos = build(root)
    except FileExistsError as e:
        print(f"{e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    advisory = load_advisory(advisory_path(root))
    print(f"built {len(repos)} synthetic demo repositories in {root} "
          "(not a real incident)", file=sys.stderr)
    report = scan_organization(repos, advisory.plan(),
                               runs=runs_provider(root), secrets=secrets_provider())
    written = _emit(report, args, advisory)
    return written or _exit_code(report)


def cmd_scan(args: argparse.Namespace) -> int:
    if args.org and args.repo:
        print("pass either --org or --repo, not both: they would be judged with "
              "different CI evidence", file=sys.stderr)
        return EXIT_BAD_INPUT
    try:
        advisory = load_advisory(args.ioc)
    except IocError as e:
        print(f"advisory rejected: {e}", file=sys.stderr)
        print(f"check it with `deptrail advisory validate {args.ioc}`; the format is "
              f"documented in {FORMAT_DOCS}", file=sys.stderr)
        return EXIT_BAD_INPUT

    errors: list[str] = []
    transient: list[str] = []
    if args.org:
        repos, errors, transient = _clone_org(args.org, Path(args.workdir),
                                              limit=args.limit)
        slug_of = lambda name: f"{args.org}/{name}"  # noqa: E731
    else:
        repos = [(Path(p).name, Path(p)) for p in args.repo]
        slug_of = (lambda name: args.slug) if args.slug else None
    if not repos and not errors and not transient:
        print("nothing to scan: pass --org or one or more --repo paths", file=sys.stderr)
        return EXIT_BAD_INPUT

    runs = _uncollected_runs("CI evidence not collected")
    secrets = None
    if args.no_ci:
        runs = _uncollected_runs("CI evidence not collected (--no-ci)")
    elif slug_of is not None:
        runs = _github_runs(slug_of, advisory.window, annotate=True)
        secrets = _github_secrets(slug_of)
    else:
        runs = _uncollected_runs(
            "CI evidence not collected (no --slug given, so no repository to query)"
        )

    # Even when every repository was skipped, the report must carry why: dropping
    # the errors here would turn "we could not look" into "there was nothing".
    report = scan_organization(repos, advisory.plan(), runs=runs, secrets=secrets,
                               allow_incomplete=args.allow_incomplete_history)
    report.errors[:0] = errors
    report.transient[:0] = transient
    written = _emit(report, args, advisory)
    return written or _exit_code(report)


# An installed wheel carries `src/deptrail` and the bundled feeds, not `docs/`, so a
# repo-relative path is a dead end for exactly the people who need it.
FORMAT_DOCS = ("https://github.com/Official-Space-AI/deptrail/blob/main/"
               "docs/ioc-format.md")


def cmd_advisory_init(args: argparse.Namespace) -> int:
    """Write an advisory to edit. Anything not supplied is left as REPLACE-ME.

    A template that validated while still full of placeholders would be worse than no
    template: the whole point of the strict loader is that a half-filled advisory fails
    before it can produce a confident CLEAN.
    """
    text = advisory_template(
        package=args.package, versions=tuple(args.version or ()),
        start=args.start, end=args.end, source=args.source,
        identifier=args.id, name=args.name,
    )
    if args.output:
        try:
            Path(args.output).write_text(text, encoding="utf-8")
        except OSError as e:
            return _write_failure(args.output, e)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text, end="")

    try:
        parse_advisory(text)
    except IocError as e:
        print(f"\nstill to fill in: {e}\n"
              f"then check it with: deptrail advisory validate {args.output or '<file>'}\n"
              f"the window is the field that decides everything — {FORMAT_DOCS}",
              file=sys.stderr)
        return EXIT_CLEAN  # a template with blanks is the expected output, not a failure
    print("this advisory is complete and valid", file=sys.stderr)
    return EXIT_CLEAN


def cmd_advisory_validate(args: argparse.Namespace) -> int:
    """Say whether an advisory is usable, before a scan depends on it."""
    try:
        advisory = load_advisory(args.ioc)
    except IocError as e:
        print(f"not usable: {e}", file=sys.stderr)
        print(f"the format is documented in {FORMAT_DOCS}", file=sys.stderr)
        return EXIT_BAD_INPUT
    start, end = advisory.window
    print(f"{advisory.id} — {advisory.name}")
    print(f"  window     {start.isoformat()} → {end.isoformat()}"
          f"  ({(end - start).days}d {((end - start).seconds // 3600)}h, inclusive)")
    print(f"  coverage   {advisory.coverage}"
          + ("" if advisory.coverage == "complete"
             else " — absence of exposure will not be provable"))
    for package in advisory.packages:
        window = "" if package.window is None else "  (own window)"
        print(f"  package    {package.name} {', '.join(package.versions)}{window}")
    print(f"  sources    {', '.join(advisory.sources)}")
    return EXIT_CLEAN


def cmd_feeds(args: argparse.Namespace) -> int:
    for name in bundled_feeds():
        advisory = load_advisory(name)
        print(f"{name}\t{advisory.id}\t{advisory.name}\t[{advisory.coverage}]")
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="deptrail",
        description="Judge which repositories installed a compromised package, "
                    "and which credentials that puts at risk.",
    )
    parser.set_defaults(func=None)
    subs = parser.add_subparsers(dest="command")

    def add_output(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--format", choices=("text", "json", "html"), default="text")
        sub.add_argument("--output", help="write the report to this file (any format)")

    demo = subs.add_parser("demo", help="judge a bundled mock infection, offline")
    demo.add_argument("--workdir", default=".deptrail-demo",
                      help="where to build the demo repositories")
    add_output(demo)
    demo.set_defaults(func=cmd_demo)

    advisory = subs.add_parser(
        "advisory", help="write and check the advisory a scan reads")
    advisory_subs = advisory.add_subparsers(dest="advisory_command")
    advisory.set_defaults(func=lambda a: (advisory.print_help(), EXIT_BAD_INPUT)[1])

    init = advisory_subs.add_parser(
        "init", help="write an advisory to fill in, or a complete one from flags")
    init.add_argument("--id", help="the advisory's own identifier, e.g. GHSA-xxxx or "
                                   "MAL-0000-1234. Never derived from the package: "
                                   "there has been more than one chalk incident")
    init.add_argument("--name", help="one line a responder will recognise months later")
    init.add_argument("--package", help="the compromised package name")
    init.add_argument("--version", action="append",
                      help="an exact malicious version; repeat for several")
    init.add_argument("--start", help="first instant the malicious artifact was "
                                      "installable, e.g. 2025-11-24T00:00:00+00:00")
    init.add_argument("--end", help="last instant it was still installable — the "
                                    "registry's removal, not the advisory's publication")
    init.add_argument("--source", help="URL the claim comes from")
    init.add_argument("--output", help="write here instead of stdout")
    init.set_defaults(func=cmd_advisory_init)

    check = advisory_subs.add_parser(
        "validate", help="check an advisory before a scan depends on it")
    check.add_argument("ioc", help="advisory file path, or a bundled feed name")
    check.set_defaults(func=cmd_advisory_validate)

    scan = subs.add_parser("scan", help="judge real repositories against an advisory")
    scan.add_argument("--ioc", required=True,
                      help="advisory file path, or a bundled feed name")
    scan.add_argument("--org", help="GitHub organization to clone and judge")
    scan.add_argument("--repo", action="append", default=[],
                      help="path to a local clone (repeatable)")
    scan.add_argument("--slug", help="owner/name of the --repo clone, so its CI runs "
                                    "and secret names can be read")
    scan.add_argument("--workdir", default=".deptrail-cache",
                      help="where organization clones are kept")
    scan.add_argument("--limit", type=int, default=200,
                      help="maximum repositories to list from the organization")
    scan.add_argument("--allow-incomplete-history", action="store_true",
                      help="accept a shallow, partial or single-branch clone as "
                           "grounds for an all-clear; off by default, because a "
                           "clone that holds less than the repository cannot "
                           "establish what the repository did")
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
    except FileNotFoundError as e:
        # An absent `git` or `gh` is an environment that cannot answer, not a
        # malformed request and not a verdict — exiting 1 here would read as
        # "rotate these credentials", and 3 would blame the caller's arguments.
        print(f"a required tool is missing: {e}", file=sys.stderr)
        return EXIT_TRANSIENT
    except subprocess.CalledProcessError as e:
        # Distinct from EXIT_INCOMPLETE: "the API call failed" is worth retrying and
        # "this history genuinely holds no lockfile" is not.
        detail = (e.stderr or "").strip()[:300]
        print(f"a command failed: {' '.join(e.cmd)}\n{detail}", file=sys.stderr)
        return EXIT_TRANSIENT
    except OSError as e:
        # A read-only workdir, a --workdir that collides with a file, a full disk.
        # Letting one escape means the interpreter exits 1, and this contract reads
        # exit 1 as "rotate these credentials".
        print(f"the tool could not run: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_TRANSIENT


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
