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

Every path that runs a scan returns one of these — a traceback escaping as exit 1
would read as "rotate now". ``--version`` and ``--help`` are the exceptions: they
print and exit 0 without reaching a verdict, so a caller must not read their 0 as
"absence of exposure was established". Nothing in `action.yml` can reach them,
because it builds the scan's argument list itself rather than forwarding a user's.
"""
from __future__ import annotations

import argparse
import errno
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .demo import advisory_path, build, runs_provider, secrets_provider
from .grading import RunHistory, annotate_installs, runs_from_github
from .history import _git_env
from .ioc import (
    COVERAGE_VALUES,
    SCHEMA_VERSION,
    Advisory,
    InstallableWindow,
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


def _configure_utf8_stdio() -> None:
    """Keep redirected Windows reports from falling back to a legacy code page."""
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("_", "-")
        reconfigure = getattr(stream, "reconfigure", None)
        if encoding not in {"utf-8", "utf8"} and reconfigure is not None:
            reconfigure(encoding="utf-8")


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
    # Windows reports writing to a directory as EACCES rather than EISDIR.  The
    # target is still a malformed request, not an environment worth retrying.
    wrong_path = error.errno in _PATH_IS_WRONG or Path(target).is_dir()
    return EXIT_BAD_INPUT if wrong_path else EXIT_TRANSIENT


def _emit(report: OrgReport, args: argparse.Namespace, advisory: Advisory | None) -> int:
    """Write the report where it was asked for. A write failure is not a verdict."""
    if args.format == "json":
        text = json.dumps(_as_dict(report, advisory), indent=2)
    elif args.format == "html":
        text = render_html(report, advisory)
    else:
        text = render_report(report, advisory)
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
        "unclassified": list(report.unresolved),
        # The dedicated keys above already carry these lines; repeating them here made
        # a JSON consumer count every gap twice while the text and HTML reports showed
        # it once. The subtraction lives on the report so all three renderers do it
        # the same way.
        "caveats": list(report.caveats),
    }
    if advisory is not None:
        def window_dict(window: InstallableWindow) -> dict:
            return {
                "start": window.start.isoformat(),
                "end": None if window.end is None else window.end.isoformat(),
                "provenance": {
                    "start": {"kind": window.provenance.start.kind,
                              "source": window.provenance.start.source},
                    "end": {"kind": window.provenance.end.kind,
                            "source": window.provenance.end.source},
                },
            }

        payload["advisory"].update({
            # `null` is the value, not a missing key: a consumer must be able to tell
            # "not known to have closed" from "we forgot to say".
            "window": window_dict(advisory.window),
            "coverage": advisory.coverage,
            "sources": list(advisory.sources),
            "packages": [
                {"name": p.name, "versions": list(p.versions),
                 "window": window_dict(advisory.window_for(p))}
                for p in advisory.packages
            ],
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
                capture_output=True, text=True, env=_git_env(),
            ).stdout.strip()
            if remote and not remote.rstrip("/").startswith(_expected_remote(org, name)):
                errors.append(
                    f"{name}: cached clone at {dest} points at {remote}, not {org}/{name}"
                )
                continue
            fetch = subprocess.run(["git", "-C", str(dest), "fetch", "--prune", "--quiet"],
                                   env=_git_env(),
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
                 str(dest)], capture_output=True, text=True, env=_git_env(),
            )
            if clone.returncode != 0:
                transient.append(f"{name}: clone failed ({clone.stderr.strip()[:120]})")
                continue
        repos.append((name, dest))
    return repos, errors, transient


def _github_runs(slug_of, window: InstallableWindow, *, annotate: bool):
    """CI history for a repository, restricted to the advisory's window.

    An open upper bound means the artifact is not known to have stopped being
    installable, so the runs that matter run up to now: bounding the query at the
    window's end would collect nothing for the whole period after it.
    """
    since, until = window.start, window.end
    if until is None:
        until = datetime.now(timezone.utc)

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
        repos = []
        for raw_path in args.repo:
            path = Path(raw_path)
            try:
                path = path.resolve()
            except RuntimeError:
                # A symlink loop is still a named path that the scan can report as
                # unreadable; it must not escape as exit 1, which means ROTATE.
                pass
            repos.append((path.name or str(path), path))
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
    # The address the operator named, never the one the checkout carries: `--org`
    # builds it here and `--slug` is typed, so ref coverage can authenticate as
    # them without the repository under suspicion choosing where that goes.
    #
    # One `--slug` cannot speak for several `--repo` paths: it names one repository
    # and would be handed to each clone in turn, so the second is compared against a
    # repository it is not. Every branch of the named one then reads as a branch
    # that clone is missing — invented gaps, and exit 2 for a checkout with nothing
    # wrong with it. (That the same `--slug` also answers for every `--repo` on the
    # CI and secrets path is older and separate: #105.)
    # `--no-ci` is documented as "no token needed", so it withholds the token --
    # not the check. Withholding the check meant the same clone exited 2 without
    # the flag and 0 with it, and the report said nothing about why.
    named = args.org or (args.slug and len(args.repo) == 1)
    trusted = ((lambda name: f"https://github.com/{slug_of(name)}.git")
               if slug_of is not None and named else None)
    report = scan_organization(repos, advisory.plan(), runs=runs, secrets=secrets,
                               allow_incomplete=args.allow_incomplete_history,
                               remote_url=trusted, authenticate=not args.no_ci)
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
    if args.end and args.end_unknown:
        print("--end and --end-unknown contradict each other; pass one",
              file=sys.stderr)
        return EXIT_BAD_INPUT
    text = advisory_template(
        package=args.package, versions=tuple(args.version or ()),
        start=args.start, end=args.end, end_unknown=args.end_unknown,
        source=args.source, identifier=args.id, name=args.name,
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


def _osv_names(args: argparse.Namespace) -> list[str]:
    """Package names to ask OSV about, from flags and from a file."""
    names = list(args.osv_package or ())
    if args.osv_packages_from:
        text = Path(args.osv_packages_from).read_text(encoding="utf-8-sig")
        names += [line.split("#", 1)[0].strip() for line in text.splitlines()]
    seen: list[str] = []
    for name in names:
        if name and name not in seen:
            seen.append(name)
    return seen


def _package_specs(args: argparse.Namespace) -> dict[str, tuple[str, ...]]:
    """Read `name@version` specs from flags and from a file, into one map.

    A scoped name contains an `@` of its own, so the split is on the last one:
    `@babel/core@7.0.0` is `@babel/core` at `7.0.0`.
    """
    lines = list(args.package or ())
    if args.packages_from:
        # utf-8-sig: a BOM survives `strip()` and turns the first entry into
        # "\ufeffchalk", which the registry answers 404 for while the operator's file
        # plainly reads chalk@5.6.1.
        text = Path(args.packages_from).read_text(encoding="utf-8-sig")
        lines += [line.split("#", 1)[0].strip() for line in text.splitlines()]

    wanted: dict[str, list[str]] = {}
    for line in lines:
        spec = line.strip()
        if not spec:
            continue
        name, sep, version = spec.rpartition("@")
        if not sep or not name or not version:
            raise ValueError(f"{spec!r}: expected name@version, e.g. chalk@5.6.1")
        # Not stripped into shape: the probe would then validate a name the fetch does
        # not use, so "chalk @5.6.1" passed the check and came back 404 at exit 4 —
        # a typo reported as the registry's problem.
        if name != name.strip() or version != version.strip():
            raise ValueError(
                f"{spec!r}: has whitespace inside it; write it as "
                f"{name.strip()}@{version.strip()}")
        wanted.setdefault(name, [])
        # The same version twice is a transcription artefact, not a second wave.
        if version not in wanted[name]:
            wanted[name].append(version)
    if not wanted and not (args.osv_package or args.osv_packages_from):
        raise ValueError("no packages given; pass --package name@version, "
                         "--packages-from FILE, or --osv-package NAME")
    return {name: tuple(versions) for name, versions in wanted.items()}


# Stands in for the packument URLs the real advisory will carry. A literal keeps
# registry.py — and urllib with it — out of every import path but derive's own.
_PROBE_URL = "https://registry.example.invalid/probe"


def _versions_from_osv(names: list[str], *, sources: list[str]) -> dict[str, tuple[str, ...]]:
    """Ask OSV which versions of each named package were malicious.

    The names are the operator's, cited to whatever writeup listed them — OSV has no
    notion of an incident, so there is no query that returns "everything compromised
    that day". What OSV does own is the version list, and taking it from there rather
    than from a keyboard is the point: a version typed slightly wrong matches no
    lockfile entry, which reads as CLEAN.

    A name OSV holds no malicious record for stops the import. It is tempting to skip
    it — the operator may have listed a package that turned out to be fine — but
    "silently contributed nothing" and "confirmed clean" are indistinguishable in the
    output, and this tool exists because that difference matters.
    """
    from .osv import OsvError, malicious_releases

    wanted: dict[str, tuple[str, ...]] = {}
    for name in names:
        records = malicious_releases(name)
        if not records:
            raise OsvError(
                f"{name}: OSV holds no malicious-package record for this name. Either "
                "it was not compromised, or it is spelled differently there — check "
                "https://osv.dev before dropping it, because a package missing from an "
                "advisory is a repository that gets cleared."
            )
        if len(records) > 1:
            listed = ", ".join(f"{r.advisory_id} {list(r.versions)}" for r in records)
            raise OsvError(
                f"{name}: OSV holds {len(records)} malicious records for it ({listed}). "
                "Which incident this advisory is about is your call, not a guess this "
                "importer should make — name the versions with --package instead."
            )
        record = records[0]
        wanted[name] = record.versions
        for url in (record.source, *record.references):
            if url not in sources:
                sources.append(url)
    return wanted


def _check_derive_inputs(wanted: dict[str, tuple[str, ...]],
                         args: argparse.Namespace) -> None:
    """Reject what the schema will reject, before any request is made.

    Raises `IocError`, which the caller turns into exit 3 — this is the caller's move.
    Doing it after the fetch reported a schema limit as "a bug in the importer", and
    the advice that came with one of those messages was actively dangerous: npm names
    must be lowercase, but `JSONStream` and `jsonstream` are two different live
    packages that both publish a 1.0.3, so lowercasing names the wrong one and the
    scan then reports CLEAN.
    """
    probe = {
        "schema_version": SCHEMA_VERSION, "id": args.id, "name": args.name,
        "ecosystem": "npm", "coverage": args.coverage,
        "window": {
            "start": "2000-01-01T00:00:00+00:00", "end": None,
            "provenance": {"start": {"kind": "derived", "source": _PROBE_URL},
                           "end": {"kind": "unknown", "source": _PROBE_URL}},
        },
        "packages": [{"name": name, "versions": list(versions),
                      "sources": [_PROBE_URL]} for name, versions in wanted.items()],
        "sources": list(args.source),
    }
    try:
        parse_advisory(json.dumps(probe))
    except IocError as e:
        hint = ""
        if "npm names are lowercase" in str(e):
            hint = (" This advisory schema accepts only lowercase npm names, and "
                    "some published packages are not lowercase. Do not lowercase the "
                    "name to get past this: a lowercase spelling can be a different "
                    "package on the registry, and a scan against it reports CLEAN. "
                    "See issue #60.")
        raise IocError(f"{e}{hint}") from e


def cmd_advisory_derive(args: argparse.Namespace) -> int:
    """Build an advisory whose window starts come from the registry, not a keyboard.

    This is the only command in the tool that reads the registry, and it is
    deliberately not a scan: the derived advisory is written to a file a human reads
    and then passes to `scan`. A verdict must not depend on a registry the incident
    may itself have taken down, and a window that differs between two runs of the
    same scan is not evidence. A scan does reach the network for its own evidence —
    clones, CI runs, and the branch list `origin` answers with — but only ever to
    *narrow* what it will claim: an unreachable remote leaves ref coverage
    unverified, never established.
    """
    # Imported here rather than at module scope: no scan should be able to read a
    # registry, and keeping urllib out of the import graph of every other command is
    # what makes that checkable instead of merely intended. A scan does reach the
    # network — through git, for clones, runs and the branch list — and never for a
    # value that could make a verdict cleaner.
    from .osv import OsvError
    from .registry import (
        PublishRecord,
        RegistryError,
        advisory_from_records,
        fetch_packument,
        publish_records,
    )

    sources = list(args.source)
    try:
        wanted = _package_specs(args)
        if args.osv_package or args.osv_packages_from:
            osv_names = _osv_names(args)
            # Merged rather than exclusive: an incident can have one package OSV has
            # not caught up with, and that one is named by hand alongside the rest.
            for name, versions in _versions_from_osv(osv_names, sources=sources).items():
                merged = list(wanted.get(name, ()))
                merged += [v for v in versions if v not in merged]
                wanted[name] = tuple(merged)
    except OsvError as e:
        print(f"{e}", file=sys.stderr)
        return EXIT_TRANSIENT
    except ValueError as e:
        print(e, file=sys.stderr)
        return EXIT_BAD_INPUT
    except OSError as e:
        # A path that is wrong is the caller's move, not a retry — the same split
        # `_write_failure` already makes twelve lines up.
        print(f"could not read {args.packages_from}: {e}", file=sys.stderr)
        wrong_path = (e.errno in _PATH_IS_WRONG
                      or Path(args.packages_from).is_dir())
        return EXIT_BAD_INPUT if wrong_path else EXIT_TRANSIENT

    # Everything the caller typed is checked before a single request goes out. A
    # rejected --source used to surface after 180 fetches, as "a bug in the importer".
    try:
        _check_derive_inputs(wanted, args)
    except IocError as e:
        print(f"{e}", file=sys.stderr)
        return EXIT_BAD_INPUT

    records: tuple[PublishRecord, ...] = ()
    for name, versions in wanted.items():
        try:
            records += publish_records(fetch_packument(name), name, versions)
        except RegistryError as e:
            # 4, not 3: by here the caller's input has already been checked against
            # the schema, so what is left is the registry being unable to answer —
            # unreachable, throttled, or holding no such package. Retrying can help.
            print(f"{e}", file=sys.stderr)
            return EXIT_TRANSIENT

    body = advisory_from_records(
        records, identifier=args.id, name=args.name,
        sources=tuple(sources), coverage=args.coverage, notes=args.notes,
    )
    text = json.dumps(body, indent=2, ensure_ascii=False) + "\n"

    # Written only after it validates. A file that exists but cannot be loaded is
    # worse than none: it invites a retry of the scan rather than of the import.
    try:
        parse_advisory(text)
    except IocError as e:
        print(f"the derived advisory does not validate. Every caller-supplied field "
              f"was checked before fetching, so this is a bug in the importer: {e}",
              file=sys.stderr)
        return EXIT_TRANSIENT

    if args.output:
        try:
            Path(args.output).write_text(text, encoding="utf-8")
        except OSError as e:
            return _write_failure(args.output, e)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text, end="")

    for record in records:
        state = "still served" if record.still_served else "withdrawn"
        print(f"  {record.name}@{record.version} published "
              f"{record.published_at.isoformat()} ({state})", file=sys.stderr)
    print("every window start is a registry publish time; every end is null, "
          "because no registry records a removal time", file=sys.stderr)
    return EXIT_CLEAN


def cmd_advisory_validate(args: argparse.Namespace) -> int:
    """Say whether an advisory is usable, before a scan depends on it."""
    try:
        advisory = load_advisory(args.ioc)
    except IocError as e:
        print(f"not usable: {e}", file=sys.stderr)
        print(f"the format is documented in {FORMAT_DOCS}", file=sys.stderr)
        return EXIT_BAD_INPUT
    start, end = advisory.window.start, advisory.window.end
    print(f"{advisory.id} — {advisory.name}")
    if end is None:
        print(f"  window     {start.isoformat()} → still open"
              "  (no removal time is recorded anywhere, so exposure cannot be "
              "ruled out after this)")
    else:
        print(f"  window     {start.isoformat()} → {end.isoformat()}"
              f"  ({(end - start).days}d {((end - start).seconds // 3600)}h, inclusive)")
    print(f"  coverage   {advisory.coverage}"
          + ("" if advisory.coverage == "complete"
             else " — absence of exposure will not be provable"))
    for package in advisory.packages:
        own = "" if package.window is None else "  (own window)"
        window = advisory.window_for(package)
        print(f"  package    {package.name} {', '.join(package.versions)}{own}")
        print(f"              window start {window.provenance.start.kind} from "
              f"{window.provenance.start.source}; end {window.provenance.end.kind} "
              f"from {window.provenance.end.source}")
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
    parser.add_argument(
        # The constant, not importlib.metadata: what is running is the code on the
        # path, and an editable install left on an older checkout would have the
        # distribution answer for a version whose code is not the one executing.
        # It cost 76 ms of import and lookup on every invocation to be wronger.
        "--version", action="version", version=f"deptrail {__version__}",
        help="print the installed version and exit",
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
    init.add_argument("--end-unknown", action="store_true",
                      help="write 'end': null — no removal time is recorded anywhere, "
                           "which is usually the truth; say it rather than guessing")
    init.add_argument("--source", help="URL the claim comes from")
    init.add_argument("--output", help="write here instead of stdout")
    init.set_defaults(func=cmd_advisory_init)

    derive = advisory_subs.add_parser(
        "derive", help="build an advisory from registry publish times (needs network)")
    derive.add_argument("--package", action="append", metavar="NAME@VERSION",
                        help="a compromised package and exact version; repeat for several")
    derive.add_argument("--packages-from", metavar="FILE",
                        help="read NAME@VERSION lines from a file; '#' starts a comment")
    derive.add_argument("--osv-package", action="append", metavar="NAME",
                        help="take this package's malicious versions from OSV rather "
                             "than typing them; repeat for several")
    derive.add_argument("--osv-packages-from", metavar="FILE",
                        help="read package names to look up in OSV from a file; "
                             "'#' starts a comment")
    derive.add_argument("--id", required=True,
                        help="the advisory's own identifier, e.g. GHSA-xxxx")
    derive.add_argument("--name", required=True,
                        help="one line a responder will recognise months later")
    derive.add_argument("--source", action="append", required=True,
                        help="URL the version list comes from; repeat for several")
    derive.add_argument("--coverage", choices=COVERAGE_VALUES, default="partial",
                        help="'partial' unless this advisory names every compromised "
                             "package, because only 'complete' can prove absence")
    derive.add_argument("--notes", help="anything a responder needs that the fields "
                                        "do not carry")
    derive.add_argument("--output", help="write here instead of stdout")
    derive.set_defaults(func=cmd_advisory_derive)

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
    _configure_utf8_stdio()
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
