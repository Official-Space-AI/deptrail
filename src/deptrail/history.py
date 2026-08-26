"""Walk the git history of a repo's lockfiles and judge exposure to an advisory.

Judgment model (shaped by adversarial review — see PR #8):

- **Graph order, never date order.** Commits are walked in the order git gives
  them along each ref's first-parent chain; commit dates are used only to
  compare against the attack window, never to order history. Date-sorting
  history lets a single skewed clock silently flip a verdict.
- **Conservative dual dates.** Rebase rewrites committer dates wholesale, so an
  interval starts at min(author, committer) of the pinning commit and ends at
  max(author, committer) of the replacing commit. Wide intervals can over-report
  exposure; they cannot under-report it. Large author/committer divergence on an
  exposing commit is surfaced as a warning.
- **Every ref testifies, merges included.** Exposure on an unmerged branch is
  still exposure — a CI runner built that branch. Each ref is walked in
  topological order over *all* its ancestry, not just the first-parent line: in
  a repo that merges pull requests, the commit that pinned a version usually
  sits on a side line, and treating it as a momentary point once made a
  two-day exposure read as CLEAN (found by replaying real history, see
  real history). An interval therefore ends at the first *descendant*
  commit whose snapshot no longer pins a named version — established with
  `merge-base --is-ancestor`, so incomparable branches widen an interval rather
  than truncating it.
- **Unreadable evidence is never silence.** Snapshot read failures, parse
  failures, shallow clones, and discovered-but-unwalkable paths all become
  warnings, and a repo with warnings and no exposures is INDETERMINATE, not
  CLEAN. A snapshot that parsed but left rows unread (``LockfileModel.unread``)
  warns the same way -- once per snapshot, whatever the window -- and cannot end
  an exposure interval either: the version may still be pinned in a row nobody
  could read.
- **A tree we cannot read is not a tree without exposure.** Only lockfiles a
  parser exists for are read: npm's two, ``pnpm-lock.yaml``, and ``yarn.lock``
  in its Berry format -- the content decides, per blob, because real histories
  switch from Yarn 1 to Berry on the same path. A tree locked with Yarn 1, Bun,
  Deno or pnpm 3's ``shrinkwrap.yaml`` is recorded in
  ``unread_trees`` and makes the repo INDETERMINATE —
  reporting CLEAN there would answer a question nobody could have looked at
  (found by replaying such repositories).
  Unlike a warning, it does not raise a grade: nothing suggests exposure either,
  so the honest outcome is "not judged".
- **A foreign lockfile counts during the window and only then.** Its existence
  interval is read from git even though its contents cannot be parsed, so a
  project that moved off Yarn years before the incident is not denied an
  all-clear forever. Whether a ``package.json`` that *no* lockfile governed
  is likewise unread is a harder question than it looks — see issue #22.
- **Only the lockfile npm would have read testifies.** When a directory holds
  both ``npm-shrinkwrap.json`` and ``package-lock.json``, npm ignores the latter,
  so at those commits so do we; scanning both invents exposure from a file that
  was never installed. ``pnpm-lock.yaml`` neither shadows nor is shadowed: it is
  another tool's install, and both installs ran.

The attack window is inclusive on both ends; held intervals are half-open
``[since, until)``.
"""
from __future__ import annotations

import base64
import os
import posixpath
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from .lockfile import LockfileModel, LockfileParseError, parse_lockfile
from .pnpmlock import parse_pnpm_lockfile
from .yarnberry import parse_yarn_berry_lockfile


class Yarn1Lockfile(LockfileParseError):
    """A ``yarn.lock`` in Yarn 1's own format: recognised, not parsed yet (issue #73).

    Its own exception because the walker must not treat it as lost evidence -- the
    tree is *unread*, the way a foreign lockfile is, and a warning would raise the
    grade of every repository that merely predates its Berry migration.
    """


def _read_yarn_lock(text: str) -> LockfileModel:
    """Berry and Yarn 1 share one basename; the content decides.

    The two signals are total on 2,743 real blobs from three full repository
    histories: 557 carry Yarn 1's header, 2,186 carry Berry's ``__metadata``, none
    carry neither. The Berry parse is tried first, so a Berry file that *also*
    carries the v1 header in a stray comment is still read -- routing on the header
    alone would have skipped its evidence wholesale. Only what Berry refuses and the
    header claims is Yarn 1; anything else keeps the refusal, the honest outcome for
    a file that claims to be a yarn.lock and is not.
    """
    try:
        return parse_yarn_berry_lockfile(text)
    except LockfileParseError:
        if "# yarn lockfile v1" in text[:400]:
            raise Yarn1Lockfile("Yarn 1 lockfiles are not parsed yet") from None
        raise

# The lockfiles this tool reads, and the parser for each. The basename decides: no
# tool writes another's filename, and a file whose content lies about it fails its
# parser and becomes a warning, never a wrong model. npm writes the first two -- a
# published package ships the second -- with one schema, so one parser reads either.
# A parsed lockfile is walked whatever the attack window, as npm's always were; only
# the foreign ones below are window-gated.
PARSED_LOCKFILES = {
    "package-lock.json": parse_lockfile,
    "npm-shrinkwrap.json": parse_lockfile,
    "pnpm-lock.yaml": parse_pnpm_lockfile,
    "yarn.lock": _read_yarn_lock,
}
# Lockfiles we can recognise but not parse yet (issue #17), and the tool that
# writes each. Finding one means that tree's installed versions are unknown to us.
# Every package manager that installs from the npm registry belongs here, because
# a name missing from this table is a repository this tool would call clean.
FOREIGN_LOCKFILES = {
    "shrinkwrap.yaml": "pnpm (v3 and earlier)",
    "bun.lock": "Bun",
    "bun.lockb": "Bun",
    "deno.lock": "Deno",  # locks npm: specifiers alongside its own
}
DATE_DIVERGENCE_WARN = timedelta(hours=48)


class GitError(RuntimeError):
    """A git invocation failed for a reason other than 'path absent at commit'."""


class Verdict(str, Enum):
    EXPOSED = "EXPOSED"
    CLEAN = "CLEAN"
    INDETERMINATE = "INDETERMINATE"


def _git_env(**extra: str) -> dict[str, str]:
    """The environment every git call here runs in.

    ``GIT_DIR`` and its relatives name a repository, and they outrank both ``-C``
    and the working directory. Inherited — from a hook, or a wrapper — they pointed
    every one of these commands at a repository other than the one being scanned,
    and the answers were about that one. The probe was taught this first and was
    the only caller taught it, which left three subprocesses to be redirected.
    """
    env = {key: value for key, value in os.environ.items()
           if key not in GIT_LOCATION_VARS}
    env.update(extra)
    return env


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        text=True, encoding="utf-8", env=_git_env(),
    )
    if result.returncode != 0:
        raise GitError(f"git {args[0]} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def _parse_iso(stamp: str) -> datetime:
    """Python 3.10's fromisoformat rejects the 'Z' suffix git may emit."""
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


@dataclass(frozen=True)
class Commit:
    sha: str
    author_time: datetime
    committer_time: datetime

    @property
    def early(self) -> datetime:
        return min(self.author_time, self.committer_time)

    @property
    def late(self) -> datetime:
        return max(self.author_time, self.committer_time)

    @property
    def dates_diverge(self) -> bool:
        return abs(self.author_time - self.committer_time) > DATE_DIVERGENCE_WARN


@dataclass(frozen=True)
class WindowQuery:
    """The minimal question an advisory asks: package, bad versions, attack window.

    ``window_end`` is ``None`` when the artifact is **not known to have stopped
    being installable**. That is the ordinary case, not an edge one: a registry
    packument keeps ``time[version]`` after a version is unpublished but records
    no removal time anywhere, so the right edge of the window cannot be computed
    and can only be asserted. ``None`` says so, and every comparison against it
    treats the window as still open — which over-reports rather than hides, the
    safe direction for this tool.
    """

    package: str
    malicious_versions: frozenset[str]
    window_start: datetime
    window_end: datetime | None

    def __post_init__(self) -> None:
        for dt in (self.window_start, self.window_end):
            if dt is None:
                continue
            if dt.tzinfo is None or dt.utcoffset() is None:
                raise ValueError("attack window datetimes must be timezone-aware")
        if self.window_end is not None and self.window_start > self.window_end:
            raise ValueError("attack window start is after its end")

    def covers(self, moment: datetime) -> bool:
        """Whether an instant falls in the window. An open end covers everything after."""
        if moment < self.window_start:
            return False
        return self.window_end is None or moment <= self.window_end


@dataclass(frozen=True)
class Exposure:
    """One piece of evidence that a lockfile pinned a compromised version.

    ``evidence`` is ``interval:<ref>`` for a first-parent interval on a ref, or
    ``commit:<sha>`` for point evidence from a merge side-line (duration unknown).
    """

    lockfile_path: str
    version: str
    since: datetime
    until: datetime | None  # None = still pinned at the tip of that ref
    commit: str
    chain: tuple[str, ...]
    evidence: str

    @property
    def still_pinned(self) -> bool:
        """Whether the ref that established this interval still pins the version.

        True for any ref, not just HEAD: a release branch whose tip still holds a
        compromised version is exactly what a remediation list must contain.
        """
        return self.until is None


@dataclass(frozen=True)
class UnreadTree:
    """A tree whose installed versions this tool could not read.

    ``path`` is the file that made this tree unreadable — a lockfile recognised
    but not parsed, or the ``package.json`` nothing locked. It is kept apart from
    ``reason`` so a caller can apply its own judgment about which trees matter: one
    under ``tests/fixtures`` is committed data, not something a workflow installs.

    ``commit`` is a commit where the tree was in this state during the window, so
    that judgment can be made against the workflows of the time rather than the
    workflows of today.
    """

    path: str
    reason: str
    commit: str = ""


@dataclass
class RepoFinding:
    """Everything the walker learned about one repository."""

    repo: Path
    exposures: list[Exposure] = field(default_factory=list)
    # Evidence that was lost: a truncated clone, an unreadable snapshot, a lockfile
    # that would not parse. Each one leaves a question open, so each one keeps the
    # repository from being cleared and widens what has to be rotated.
    warnings: list[str] = field(default_factory=list)
    # Observations about the history that cost no evidence — a rewritten date, a
    # commit older than its parent. They are printed, and that is all: treating
    # them as lost evidence put every credential of a rebased repository on the
    # rotation list.
    diagnostics: list[str] = field(default_factory=list)
    # Ways this *clone* holds less than the repository does: shallow, partial,
    # single-branch. Kept apart from ``warnings`` because the remedy differs — a
    # deeper clone fixes these and nothing fixes a corrupt lockfile — and because
    # only these may be waived by ``--allow-incomplete-history``.
    incomplete: list[str] = field(default_factory=list)
    lockfiles_seen: int = 0
    # Trees whose dependencies this tool cannot read at all: a lockfile in a
    # dialect it does not parse, or a Node project with no lockfile in history.
    # Kept apart from ``warnings`` because the two deserve different answers —
    # a warning means evidence about a tracked lockfile was lost, so an install
    # is possible; an unread tree means there was never anything to look at.
    unread_trees: list[UnreadTree] = field(default_factory=list)

    @property
    def exposed(self) -> bool:
        return bool(self.exposures)

    @property
    def verdict(self) -> Verdict:
        """CLEAN is only claimable when nothing was exposed AND nothing went unread."""
        if self.exposures:
            return Verdict.EXPOSED
        if self.warnings or self.unread_trees or self.incomplete:
            return Verdict.INDETERMINATE
        return Verdict.CLEAN


def is_shallow(repo: Path) -> bool:
    return _git(repo, "rev-parse", "--is-shallow-repository").strip() == "true"


def _config(repo: Path, key: str) -> str:
    """One git config value, empty when unset. Never raises for a missing key."""
    result = subprocess.run(
        ["git", "-C", str(repo), "config", "--get-all", key],
        capture_output=True, text=True, env=_git_env(),
    )
    return result.stdout.strip() if result.returncode == 0 else ""


# `git ls-remote` against a real GitHub remote measured 675 ms, and 18 ms against a
# local one, so the ceiling is not there to bound the normal case — it is there so a
# remote that accepts the connection and then says nothing cannot hang a scan.
LS_REMOTE_TIMEOUT = 10.0
# Every real advertisement is a line per ref; the largest repository anyone scans
# is nowhere near this. It is a ceiling on a hostile endpoint, not on a remote.
MAX_ADVERTISEMENT = 32 * 1024 * 1024


# Transports a repository under investigation may send us to. The allowlist is the
# point, not its contents: `ext::` runs a command named in the URL, and a config
# that turns it back on is config the scanned repository carries. Named here so an
# operator can narrow it further from the environment, which wins.
REMOTE_PROTOCOLS = "https:http:git:ssh:file"
# `user@host:path`, git's scp-like remote spelling: a remote, never a local path.
_SCP_LIKE = re.compile(r"^[^/:]+(@[^/:]+)?:(?!//)")
# Variables that name a repository. Inherited, they outrank both the directory the
# query runs in and any ceiling set for it — a scan launched from a git hook, whose
# GIT_DIR points at the very clone under investigation, had the isolation below
# undone and executed a command planted in that clone's config.
GIT_LOCATION_VARS = frozenset({
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
})


# Settings and credential providers that arrive through the environment rather
# than a file, so blanking `HOME` and the config files does not touch them. The
# askpass pair hands over a stored password on request; the ssh pair names a
# command this code would then run against an address the scanned repository
# chose; `GIT_CONFIG_COUNT` and `GIT_CONFIG_PARAMETERS` are config with no file at
# all, and both were measured putting an `http.extraHeader` and a live
# `credential.helper` into the probe -- git exports the second to every child of a
# `git -c` command, so a scan run from an alias or a hook carries it.
#
# `GIT_SSL_NO_VERIFY` is here because the probe carries a credential now and
# unverified TLS hands it to whoever is on the path. `GIT_SSL_CAINFO` and the
# proxy variables are deliberately kept: naming a CA still verifies, and they are
# the only way a network behind an intercepting proxy works at all.
PROBE_STRIPPED_VARS = frozenset({
    "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_ASKPASS",
    "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND",
    "SSH_AUTH_SOCK", "GIT_SSL_NO_VERIFY",
})

# What a report calls the address the operator named. A clone may name one of its
# own remotes this, so the two are told apart by role and the collision is renamed
# where it is printed.
NAMED_ADDRESS = "the repository you named"

# The only hosts a token may be sent to, and the only ones whose ambient token is
# taken to be theirs.
GITHUB_HOSTS = ("github.com", "www.github.com")


# What a repository's ref coverage came out as, keyed by the checkout, the
# address the operator named and whether a credential may go with the query --
# the three things the answer is a function of.
CoverageCache = dict[tuple[str, str | None, bool],
                     tuple[str | None, str | None]]


def _without_injected_config(env: dict[str, str]) -> dict[str, str]:
    """The same environment with git's settings-by-environment removed.

    What still reaches the probe, and is not removable here: the ssh client reads
    ``~/.ssh`` from the *account*, not from ``HOME`` — measured, OpenSSH ignores a
    redirected ``HOME`` — so an ssh remote is still contacted with the operator's
    own key. The claim this makes is therefore narrow: no git config from a file,
    no credential asked for on demand, no command named by the environment, and
    nothing from a URL's userinfo.
    """
    return {key: value for key, value in env.items()
            if key not in PROBE_STRIPPED_VARS
            and not key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))}


def _remotes(repo: Path) -> list[str]:
    """Every remote this clone is configured with.

    Choosing one was the mistake, and three false all-clears came out of it in
    turn: the name ``origin`` was assumed and a clone made with ``-o upstream``
    answered nothing; then ``origin`` was preferred and a fork added afterwards
    took every check away from the remote the clone came from; then the branch's
    own upstream was consulted and named a remote the clone had never seen. There
    is no field that records where a checkout came from, so no answer to pick —
    what a clone holds is compared against every remote it has, and a branch none
    of them can account for is one the walk cannot testify about.

    ``$GIT_DIR/remotes/<name>`` is read too. It predates the config sections, git
    still honours it for fetching, and ``git remote`` does not list it — a clone
    using one looked to this code like a clone with no remote at all, which costs
    nothing and says nothing.
    """
    names = {line.strip()
             for line in _local_git(repo, ["remote"], "").stdout.splitlines()
             if line.strip()}
    git_dir = _local_git(repo, ["rev-parse", "--git-dir"], "").stdout.strip()
    if git_dir:
        root = Path(git_dir)
        root = root if root.is_absolute() else repo / root
        # Two spellings predate the config sections, git still fetches through
        # both, and `git remote` lists neither.
        for legacy in (root / "remotes", root / "branches"):
            if legacy.is_dir():
                names |= {entry.name for entry in legacy.iterdir()
                          if entry.is_file()}
    return sorted(names)


def _fetches_every_head(refspec: str) -> bool:
    """Whether this remote's refspec brings every branch the remote has.

    One refspec per line, and each line judged on its own: testing the whole blob
    for a ``*`` meant that adding the documented tags refspec to a single-branch
    clone — one line, no other change — made it look like a full one.
    """
    wide = False
    for line in refspec.splitlines():
        source = line.strip().lstrip("+").partition(":")[0]
        # A negative refspec removes branches from whatever the positive ones
        # brought, so a clone carrying one has not fetched every head no matter
        # what else it says.
        if source.startswith("^"):
            return False
        # And only the whole namespace counts. `refs/heads/release/*` is a
        # wildcard that fetches nothing outside `release/`, and reading any `*`
        # as completeness cleared every branch beside it.
        if source in ("refs/*", "refs/heads/*"):
            wide = True
    return wide


def _remote_url(repo: Path, remote: str) -> str | None:
    """A remote's URL as a value, or ``None`` when there is nothing safe to use.

    A URL beginning with ``-`` would reach git as an option rather than a remote,
    and a relative local path is written against the clone, so it is resolved here
    while that is still meaningful.
    """
    # `get-url` resolves `url.<base>.insteadOf`, which the raw config value does
    # not: a clone whose config rewrites its remote fetches from one place while
    # `remote.<name>.url` names another, and the probe asked the decoy. Reading
    # config executes nothing — the settings that run commands run on transport,
    # which is still done from the neutral directory below.
    resolved = _local_git(repo, ["remote", "get-url", remote], "")
    lines = (resolved.stdout if resolved.returncode == 0
             else _config(repo, f"remote.{remote}.url")).splitlines()
    url = lines[0].strip() if lines else ""
    # A control character would let the value break out of the config line it is
    # written on, which is the one way a URL could become a setting.
    if not url or url.startswith("-") or any(c < " " or c == "\x7f" for c in url):
        return None
    # Only something git would read as a local path may be resolved against the
    # clone. Without the check, `https://host/repo.git` became the candidate path
    # `<checkout>/https:/host/repo.git`, and a checkout carrying a bare repository
    # there — one advertising exactly the branches already held — had its real
    # remote's missing branches cleared by a decoy it shipped itself.
    if "://" not in url and not _SCP_LIKE.match(url):
        local = repo / url
        if local.exists():
            return str(local.resolve())
    return _without_userinfo(url)


def _without_userinfo(url: str) -> str:
    """The same URL with any embedded credential dropped.

    Writing the URL to a config file instead of a command line does not keep a
    token out of process listings, because git hands the full URL to its own
    transport helper: ``git remote-https origin https://user:token@host/path``
    shows in ``ps`` and in ``GIT_TRACE`` whatever this code does.

    Over http and https the username is a credential slot, not a name: a personal
    access token with an empty password is the documented spelling, and keeping
    "the username, since a username is not a secret" sent one as Basic auth to a
    host the scanned repository chose — measured against a local server. Nothing
    from the userinfo survives there. Over ssh it does: authentication is by key,
    the ``git`` in ``ssh://git@github.com/…`` is the account being reached rather
    than a secret, and dropping it probed as whatever OS user the responder is.
    """
    scheme, separator, rest = url.partition("://")
    authority, slash, tail = rest.partition("/")
    userinfo, at, host = authority.rpartition("@")
    if not separator or not at:
        return url
    if scheme.endswith("ssh"):
        return f"{scheme}://{userinfo.partition(':')[0]}@{host}{slash}{tail}"
    return f"{scheme}://{host}{slash}{tail}"


def _host_of(value: str) -> str:
    """The hostname in a URL, or in a bare ``host[:port]``, lowercased.

    Anything unrecognisable comes back as itself rather than as the empty string.
    Read as ``partition("://")[2]``, a value with no scheme — ``ghe.example.com``,
    which is how an operator would type it — yielded ``""``, which was taken for
    "nobody named a host" and sent an enterprise token to github.com.
    """
    scheme, separator, rest = value.partition("://")
    authority = (rest if separator else scheme).partition("/")[0]
    return authority.rpartition("@")[2].partition(":")[0].lower()


def _github_authorization(url: str) -> str | None:
    """A Basic header for a GitHub URL when the environment holds a token.

    Only for an address the operator named, and only for github.com: the point of
    a trusted URL is that nothing about where this goes came from the repository,
    and a token is worth carrying only under exactly that condition.
    """
    # Over plain http the header is on the wire before a redirect could upgrade it,
    # so only the scheme that carries it inside TLS may carry it at all.
    if not url.startswith("https://") or _host_of(url) not in GITHUB_HOSTS:
        return None
    # `GH_TOKEN` and `GITHUB_TOKEN` are github.com credentials by `gh`'s own rule —
    # a GitHub Enterprise Server host is served by `GH_ENTERPRISE_TOKEN`, which this
    # code never reads — so `GH_HOST` must not withhold them: it picks `gh`'s
    # default target, not a token's home, and testing it here refused a github.com
    # PAT for github.com and turned a correct scan from exit 0 into exit 2.
    #
    # `GITHUB_SERVER_URL` is the one that does say where a token lives: Actions sets
    # it to the instance that minted the run's token, so on a GHES runner
    # `GH_TOKEN: ${{ github.token }}` — which this project's own `action.yml` writes
    # — is that instance's. `gh` never consults it, so the `--hostname` pin below
    # cannot catch that one.
    server = (os.environ.get("GITHUB_SERVER_URL") or "").strip()
    token = ""
    if not server or _host_of(server) in GITHUB_HOSTS:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        # The operator's own login, through the tool this scan already reads CI runs
        # and secret names with, so nothing new is being asked of them. Pinned to the
        # host it will be sent to, and asked with the environment's tokens taken
        # away: the flag does not outrank them, so `gh` handed straight back the
        # credential the check above had just refused. If that one were ours to use
        # it was used above, so here it is only in the way.
        env = _git_env()
        env.pop("GH_TOKEN", None)
        env.pop("GITHUB_TOKEN", None)
        # An absent credential helper is an absent credential, not a statement about
        # the remote. Unguarded, `gh` merely not being installed raised out of here
        # and out of `_remote_heads` before `ls-remote` was ever built, and
        # `_ref_coverage` read that as the named address falling silent — so a
        # public, complete clone was reported incomplete on a box without `gh`, with
        # advice to go and set a token. A `gh` that hangs arrives by `TimeoutExpired`.
        try:
            asked = subprocess.run(
                ["gh", "auth", "token", "--hostname", "github.com"],
                capture_output=True,
                text=True, check=False, timeout=LS_REMOTE_TIMEOUT, env=env)
        except (OSError, subprocess.SubprocessError):
            return None
        token = asked.stdout.strip() if asked.returncode == 0 else ""
    if not token:
        return None
    pair = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return f"Authorization: Basic {pair}"


def _remote_heads(repo: Path, remote: str = "origin", *,
                  trusted_url: str | None = None,
                  authenticate: bool = True) -> dict[str, str] | None:
    """The remote's branch names and tips, or ``None`` when it could not be asked.

    The repository under investigation may be the compromised one, so its
    ``.git/config`` is input and not settings — and git config is a place where
    commands hide. Both ``core.sshCommand`` and ``remote.origin.uploadpack`` were
    measured executing a planted value during ``ls-remote``, and overriding each in
    turn is a game with no last move: the URL is taken out as a *value* and the
    query runs from a throwaway repository elsewhere, so that config is never read.

    The operator's own config is not read either, and that is the harder half. It
    is where credentials live, and the URL being asked about comes from the
    repository under suspicion: an unscoped ``http.extraHeader`` was measured
    reaching a host the scanned checkout named, and clearing that one key by name
    does not work — a URL-scoped header outranks the override, still goes out, and
    takes the unscoped one with it. So the probe carries no credential it can be
    given: no git config from a file, none injected through the environment, no
    askpass, and nothing from a
    URL's userinfo. An ssh key on the account's own disk is the exception the
    docstring on ``_without_injected_config`` records. What it
    costs is real: a private remote comes back unverified rather than answered, as
    does one behind a proxy the operator configured globally. The alternative is
    handing whatever the machine holds to whatever address a compromised
    repository writes down, and "unverified" is a caveat while that is a breach.

    ``GIT_TERMINAL_PROMPT=0`` keeps the same remote from stopping the scan at an
    interactive password prompt; it fails in well under a second instead.
    """
    # A trusted URL is one the *operator* named — `--org` builds it, `--slug` is
    # typed — so nothing about where this query goes came from the repository under
    # suspicion, and the operator's own credentials can go with it. That is the
    # whole difference: carrying a credential was never the danger, carrying one to
    # an address a possibly compromised checkout chose was.
    # It is still checked the way a remote's URL is. `_remote_url` is what rejects a
    # value that would reach git as an option or break out of the config line it is
    # written on, and what drops an embedded credential -- git hands the whole URL
    # to its transport helper, so `ps` and `GIT_TRACE` see a token in one however it
    # was written here. Trusted means the *address* is the operator's, not that the
    # string is safe.
    url = trusted_url if trusted_url else _remote_url(repo, remote)
    if url is None or url.startswith("-") or any(c < " " or c == "\x7f" for c in url):
        return None
    url = _without_userinfo(url)
    # An operator may narrow the transports; they may not widen them. `setdefault`
    # deferred to whatever was already in the environment, and a permissive value
    # there put `ext::` — which runs the command named in the URL, and the URL comes
    # from the repository under investigation — back within reach.
    allowed = set(REMOTE_PROTOCOLS.split(":"))
    # Empty is git's own way of saying "allow nothing", so it is a setting and not
    # an absence: reading it as unset inverted the strictest narrowing into the
    # broadest list.
    if os.environ.get("GIT_ALLOW_PROTOCOL") is not None:
        allowed &= set(os.environ["GIT_ALLOW_PROTOCOL"].split(":"))
    env = _git_env()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ALLOW_PROTOCOL"] = ":".join(sorted(allowed))
    with tempfile.TemporaryDirectory(prefix="deptrail-refs-") as probe:
        # No config but the one written below. `GIT_CONFIG_GLOBAL` and
        # `GIT_CONFIG_SYSTEM` say it outright on git 2.32 and later, and pointing
        # `HOME` at the empty probe says the same thing to every git that has ever
        # looked there — belt and braces, because a version that quietly ignored the
        # first pair would read the operator's credentials and never say so.
        env = _without_injected_config(env)
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["HOME"] = env["XDG_CONFIG_HOME"] = env["USERPROFILE"] = probe
        started = subprocess.run(["git", "init", "-q", probe], env=env,
                                 capture_output=True, text=True, check=False)
        if started.returncode != 0:
            return None
        config = Path(probe) / ".git" / "config"
        # The URL goes into a config file this code writes rather than onto a
        # command line: a clone whose origin embeds a token — CI writes them that
        # way — would otherwise show it to every `ps` on the machine for as long as
        # the query runs. It is written last, so nothing follows it to be swallowed.
        # Quoted the way git config reads it back: a Windows path's backslashes are
        # escapes, and `#` or `;` start a comment, so an interpolated value either
        # truncated the URL or made the file unparseable.
        quoted = url.replace("\\", "\\\\").replace('"', '\\"')
        settings = f'[remote "origin"]\n\turl = "{quoted}"\n'
        # In the shipped Action the token arrives as GH_TOKEN, which git does not
        # read, while `actions/checkout` leaves its own credential in the config of
        # the repository being scanned -- the one config this probe refuses to read.
        # Without this the Action's whole reason for the check goes unauthenticated
        # on a private repository, which is exactly where it was needed. It is
        # written to the file rather than passed as an argument, because `ps` sees
        # argv, and only for an address the operator named: keyed on the URL alone,
        # a scan with GH_TOKEN in its environment -- every Action, and `--no-ci`
        # among them -- attached it to a github.com URL read from the checkout's own
        # config, which is an address the repository chose.
        if trusted_url and authenticate:
            if (header := _github_authorization(url)) is not None:
                quoted_url = url.replace("\\", "\\\\").replace('"', '\\"')
                settings += (f'[http "{quoted_url}"]\n\textraHeader = "{header}"\n')
        # Never a credential helper. Letting one answer meant that when the token
        # was stale GitHub replied 401, git asked the helper, git then ran
        # `credential erase`, and a read-only scan deleted the operator's saved
        # GitHub login -- from an ordinary run, and from `pytest` with every test
        # green. The header above is the only credential this probe may hold.
        settings += "[credential]\n\thelper = \n"
        # And it goes to the address it was written for and nowhere else. Git's
        # default `followRedirects = initial` rebases the remote URL on the redirect
        # target: measured, curl stripped the header on the redirect leg and then
        # sent it in full on the protocol-v2 POST that followed, to a different host
        # -- which also became the source of the branch list.
        settings += "[http]\n\tfollowRedirects = false\n"
        config.write_text(config.read_text() + settings)
        # The advertisement lands in a file, not in this process: the timeout bounds
        # how long a hostile endpoint may talk, and nothing bounded how much, so a
        # remote that streams could exhaust the scanner before the clock ran out.
        # The cap is enforced while the transfer runs, not after it: checking the
        # size once the child had exited bounded what this process reads and let a
        # fast endpoint write for the whole ten seconds first.
        sink = Path(probe) / "advertisement"
        with sink.open("wb") as buffered:
            child = subprocess.Popen(
                ["git", "-C", probe, "ls-remote", "--heads", "origin"],
                stdout=buffered, stderr=subprocess.DEVNULL, env=env,
            )
            deadline = time.monotonic() + LS_REMOTE_TIMEOUT
            while True:
                try:
                    code = child.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if (time.monotonic() > deadline
                        or sink.stat().st_size > MAX_ADVERTISEMENT):
                    child.kill()
                    child.wait()
                    code = None
                    break
        # Polling alone is not the cap: an advertisement that finishes inside the
        # first interval is never measured by the loop, so the size is checked once
        # more when the child is done.
        if code != 0 or sink.stat().st_size > MAX_ADVERTISEMENT:
            return None
        advertisement = sink.read_text(encoding="utf-8", errors="replace")
    heads: dict[str, str] = {}
    for line in advertisement.splitlines():
        tip, _, ref = line.partition("\t")
        # A ref whose name git will not accept is advertised with an all-zero id,
        # and the peeled rule below would then overwrite a real branch's tip with
        # it — reporting a branch this clone holds as one it cannot walk.
        if not tip or set(tip) == {"0"} or not ref.startswith("refs/heads/"):
            continue
        name = ref[len("refs/heads/"):]
        if name.endswith("^{}"):
            # A branch pointing at an annotated tag advertises the tag object and
            # then the commit it peels to. The commit is the one everything local is
            # compared against: keeping the tag object instead, its id matched
            # nothing and `rev-list` answered about the commit, so a branch the walk
            # could not reach at all was read as covered.
            heads[name[:-3]] = tip
        else:
            heads.setdefault(name, tip)
    return heads


def _local_git(repo: Path, args: list[str], stdin: str) -> subprocess.CompletedProcess:
    """A local query in the clone, with lazy fetching off.

    A promisor clone asked about an object it does not hold goes and fetches it,
    which would put an unbounded network call — no timeout, no prompt guard —
    inside what is supposed to be a local membership test, and would write to the
    repository besides. Absent is the answer here, not something to go and fix.
    """
    return subprocess.run(
        ["git", "-C", str(repo), *args], input=stdin,
        capture_output=True, text=True, encoding="utf-8", check=False,
        env=_git_env(GIT_NO_LAZY_FETCH="1"),
    )


def _heads_not_here(repo: Path, heads: dict[str, str]) -> list[str]:
    """Which of the remote's branches this clone cannot walk.

    The question is reachability, not naming: what the walk can testify about is
    the commits its refs lead to. Matching branch *names* looked equivalent and is
    not — a clone whose ``origin/feature`` is behind the remote holds the name and
    not the commits, and blessing it cleared a repository at exit 0 while the
    malicious pin sat on the remote's own tip. So each advertised tip is asked for
    directly: held under another name still counts, a ref that has moved past it
    still counts, and a tip nothing leads to is a branch this clone cannot judge.

    ``HEAD`` is enumerated with the refs because ``_refs`` walks it: a detached
    checkout can be the only thing holding a tip, and leaving it out reported a
    complete clone as missing every branch it had.

    Two subprocesses answer the whole remote, whatever its size. The exact-tip set
    settles most branches without either — a clone that fetched a branch and has
    not fallen behind points a ref straight at it — then one ``cat-file`` says
    which of the rest are here at all, and one ``rev-list`` says which of *those*
    no ref leads to. Asking per branch instead cost a process per unfetched tip,
    which on an origin with hundreds of branches is the case this check exists for.
    """
    tips = set()
    for line in _git(repo, "for-each-ref", "--format=%(objectname) %(refname)",
                     "refs/heads", "refs/remotes").splitlines():
        tip, _, ref = line.partition(" ")
        # Exactly the refs `_refs` hands the walker, or this answers for refs nobody
        # walks: it drops every name ending in `/HEAD` as the alias it usually is,
        # and a remote branch *called* `HEAD` lands there too — fetched, counted
        # here as held, and never walked. A pin on it was reported at exit 0, which
        # is #27 again through the check written to close it.
        if not ref.endswith("/HEAD"):
            tips.add(tip)
    # HEAD only once it resolves. An unborn HEAD — a clone that fetched but never
    # checked out — made `^HEAD` a fatal argument, and one fatal argument was read
    # below as "nothing is reachable", so a complete clone was told it was missing
    # every branch it had.
    head = _local_git(repo, ["rev-parse", "--verify", "--quiet", "HEAD"], "")
    if head.returncode == 0 and head.stdout.strip():
        tips.add(head.stdout.strip())
    if not heads:
        return []
    # One batch decides what this clone holds at all — the tips asked about and its
    # own refs together. Both sides need it: a ref can name an object that is not
    # here (a pruned or interrupted fetch leaves them behind), and matching a remote
    # tip against such a ref proved coverage by a commit nobody has. Excluding by
    # object rather than by name is the other half, and keeps one such ref from
    # making `rev-list` fatal and every diverged branch read as missing.
    here = set()
    known = _local_git(repo, ["cat-file", "--batch-check"],
                       "\n".join({*heads.values(), *tips}) + "\n")
    for line in known.stdout.splitlines():
        name, _, rest = line.partition(" ")
        if rest and not rest.startswith("missing"):
            here.add(name)
    held = tips & here
    candidates = {name: tip for name, tip in heads.items() if tip not in held}
    if not candidates:
        return []
    wanted = {tip for tip in candidates.values() if tip in here}
    unreachable = {tip for tip in candidates.values() if tip not in here}
    if wanted:
        walked = _local_git(
            repo, ["rev-list", "--no-walk", "--stdin"],
            "\n".join([*wanted, *(f"^{tip}" for tip in held)]) + "\n")
        # A refusal is not evidence of coverage: read it as nothing reachable.
        unreachable |= (set(walked.stdout.split()) if walked.returncode == 0
                        else wanted)
    return sorted(name for name, tip in candidates.items() if tip in unreachable)


def incomplete_history(repo: Path,
                       coverage_cache: CoverageCache
                       | None = None,
                       trusted_url: str | None = None, authenticate: bool = True,
                       ) -> tuple[list[str], list[str]]:
    """How much less this clone holds than the repository does, and what that costs.

    Returns (reasons that stop an all-clear, observations that only inform).

    A **shallow** clone is missing commits outright, and a **single-branch** clone
    fetched one refspec, so a branch nobody fetched cannot testify. Neither can be
    cleared.

    A **partial** clone is different, and treating it as equivalent was
    over-reporting: it has every commit, and its blobs arrive from the promisor
    remote on demand. Whether that worked is not a prediction to make in advance —
    ``_read_snapshot`` records a warning for every snapshot it could not read, so if
    that list is empty the run *did* read every state its verdict depends on and the
    repository is as fully judged as a full clone would be. So a partial clone is an
    observation, and the read failures are the evidence.

    A checkout built by ``git init`` plus ``git fetch origin <branch>`` defeats all
    three: it keeps the wildcard refspec, is not shallow and has no promisor, yet
    holds one branch, and it used to be cleared at exit 0 with the malicious pin
    sitting on a branch nobody fetched (#27). No local signal separates it from a
    complete checkout — ``actions/checkout`` with ``fetch-depth: 0`` fetches every
    head and, being ``init`` plus ``fetch`` itself, leaves the same wildcard refspec
    and the same absent ``origin/HEAD``; only the ref *count* differs, and a count
    means nothing without knowing what the remote has. So this asks: the remote's
    branch list, compared against what the clone can walk, names the branches that
    were never fetched. When a remote *the repository names* cannot be reached the
    answer is an observation and not a reason, because refusing every offline scan
    its all-clear would cry wolf at complete clones; when the address the *operator*
    named cannot be asked it is a reason, because nothing else can answer for it and
    the scanned repository is what chooses the alternatives. When no remote is
    configured there is nothing to compare and no penalty, which is what
    ``deptrail demo`` produces.
    """
    reasons, notes = [], []
    if is_shallow(repo):
        reasons.append(
            "shallow clone: history is truncated, absence of exposure is not evidence"
        )
    for remote in _remotes(repo):
        fetch = _config(repo, f"remote.{remote}.fetch")
        if fetch and not _fetches_every_head(fetch):
            reasons.append(
                f"single-branch clone ({remote}: {fetch.splitlines()[0]}): other "
                "refs, if the remote has any, were not fetched, and exposure on a "
                "branch nobody fetched is still exposure"
            )
        if _config(repo, f"remote.{remote}.promisor") == "true":
            filtered = (_config(repo, f"remote.{remote}.partialclonefilter")
                        or "unknown filter")
            notes.append(
                f"partial clone ({filtered}): lockfile contents were fetched on "
                "demand; any that could not be read are listed as unreadable "
                "snapshots"
            )
    reason, note = _ref_coverage(repo, coverage_cache, trusted_url, authenticate)
    if reason:
        reasons.append(reason)
    if note:
        notes.append(note)
    return reasons, notes


def _ref_coverage(repo: Path,
                  cache: CoverageCache | None = None,
                  trusted_url: str | None = None, authenticate: bool = True,
                  ) -> tuple[str | None, str | None]:
    """What the remotes' branch lists say about this clone: (reason, observation).

    Every remote is asked, plus the address the operator named if there is one, and
    a branch none of them can account for is one the walk cannot testify about. A
    fork checkout is told that its upstream's unfetched branches are unfetched,
    which is true and is waivable with ``--allow-incomplete-history``; the
    alternative — picking one — was four separate false all-clears, the last of
    them from letting a named address stand in for the rest.

    ``cache`` is keyed by repository because the answer is a property of the
    checkout and not of the advisory: ``scan_organization`` walks every repository
    once per advisory package, and without it a 180-package advisory over 200
    repositories would have asked 36,000 times.
    """
    # Keyed on what the answer is a function of. It was the checkout alone, which
    # was true until the address the operator named became one of the sources: with
    # one cache reused, the first call's non-blocking caveat was handed back in
    # place of the second's blocking reason. No shipped caller varies it today —
    # ``scan_organization`` builds the cache inside its per-repository loop — but
    # hoisting that cache out of the loop is the obvious optimisation, and the key
    # is what would make it wrong.
    key = (str(repo), trusted_url, authenticate)
    if cache is not None and key in cache:
        return cache[key]
    found: dict[tuple[str, str], str] = {}
    # The address the operator named is asked *as well as* the clone's own remotes,
    # never instead of them. Replacing them looked reasonable -- they named it, so
    # it is the authority -- and it put #27 back: when the named address could not
    # answer, nothing else was asked, the gap became an observation, and the same
    # clone that exits 2 without `--slug` exited 0 with it.
    asked: list[tuple[str | None, str | None]] = [
        (remote, None) for remote in _remotes(repo)]
    if trusted_url:
        asked.insert(0, (None, trusted_url))
    answered: list[str] = []
    silent_named: list[str] = []
    silent_own: list[str] = []
    for remote, url in asked:
        try:
            heads = _remote_heads(repo, remote or "origin", trusted_url=url,
                                  authenticate=authenticate)
        except (OSError, subprocess.SubprocessError):
            heads = None
        # A remote's name is a config section or a filename, so a clone can call one
        # of its own remotes exactly what this code calls the operator's address --
        # and the report then said "not verified against the repository you named,
        # and rests on the repository you named" and filed that remote's gaps under
        # the operator's address. Planting it needs write access to `$GIT_DIR`, which
        # is what every other defence here already assumes, so the name is
        # disambiguated rather than trusted.
        label = (NAMED_ADDRESS if url is not None
                 else f'remote "{remote}"' if remote == NAMED_ADDRESS else remote)
        if heads is None:
            # `url` is set only for the address the operator named. The two roles are
            # kept in separate lists rather than recovered afterwards by comparing
            # label text, which is the same collision again.
            (silent_named if url is not None else silent_own).append(label)
            continue
        # An empty advertisement is a source that said nothing. Counted as an answer,
        # a remote serving no refs -- or one whose URL resolves to the checkout
        # itself -- was named below as what a clean result rested on.
        if heads:
            answered.append(label)
        # One line per gap, and a gap is a branch *at a tip*: the named address and
        # a remote of the clone are usually the same repository, so the same branch
        # at the same commit is one gap and saying it twice reads as two. Two
        # remotes advertising that name at different commits are two, and keying on
        # the name alone dropped the second — fetching one source would have left
        # the other unexamined.
        for branch in _heads_not_here(repo, heads):
            found.setdefault((branch, heads[branch]), label)
    missing = [f"{label}/{branch}" for (branch, _tip), label in found.items()]
    reason = note = None
    if missing:
        # The names are the point — they are what a responder re-fetches — but a
        # repository can have hundreds of branches, and a reason that prints them
        # all is a reason nobody reads.
        shown = ", ".join(sorted(missing)[:5])
        if len(missing) > 5:
            shown += f", and {len(missing) - 5} more"
        reason = (f"{len(missing)} branch(es) on this clone's remote(s) are not in "
                  f"it ({shown}): a branch this clone cannot walk cannot testify, "
                  "and exposure on it is still exposure")
    silent = silent_named + silent_own
    if silent_named:
        # Withholding the token withheld the *answer*: on a private repository the
        # unauthenticated query is refused, the clone's own remote is that same
        # address and is refused too, so the check ran, had nothing to say, and the
        # clone was cleared -- measured, exit 2 without `--no-ci` and 0 with it, over
        # a poisoned pin on an unfetched branch. Nor does another remote answering
        # stand in for the named one, which was the first attempt at this: the
        # *scanned repository* chooses which remotes it has, so a stale mirror or a
        # plain decoy was enough to clear the clone.
        #
        # The remedy is named only where it is known to be one -- a deleted
        # repository, a mistyped slug and no network all arrive here too.
        remedy = (" A private repository needs a token — GH_TOKEN, GITHUB_TOKEN or "
                  "`gh auth token` — and `--no-ci` withholds it." if not authenticate
                  else " It was unreachable, or it refused the query: check the "
                       "address, and for a private repository that GH_TOKEN, "
                       "GITHUB_TOKEN or `gh auth token` holds a credential for it.")
        beside = (f" ({', '.join(silent_own)} could not be asked either)"
                  if silent_own else "")
        silence = (f"the address you named could not be asked{beside}: without its "
                   "branch list, a clone that fetched only some of them cannot be "
                   "told from one that fetched them all, and no other remote can "
                   "answer for it — the scanned repository chooses those." + remedy)
        # Both block, and the branches are the actionable half, so the gaps stay the
        # reason and the silence is said beside them rather than twice.
        if reason is None:
            reason = silence
        else:
            note = silence
    elif silent and answered:
        # "Coverage was not verified" is false on the shipped Action's ordinary
        # shape, where the named address answers in full and only the checkout's own
        # `origin` -- whose credential lives in the config this probe refuses to read
        # -- cannot be asked. Unqualified, it fired on exactly the runs where the
        # feature was working.
        note = (f"ref coverage was not verified against {', '.join(silent)}, and "
                f"rests on {', '.join(answered)}: a branch that exists only on a "
                "remote none of those could speak for would not have been seen")
    elif silent:
        note = (f"ref coverage was not verified against {', '.join(silent)}: a "
                "remote that cannot be reached, or has no URL to ask, leaves a "
                "checkout that fetched only some branches looking like a complete "
                "one")
    outcome = (reason, note)
    if cache is not None:
        cache[key] = outcome
    return outcome


def _paths_with_basename(repo: Path, basenames: tuple[str, ...]) -> list[str]:
    """Every path where one of these files ever lived on any ref.

    ``--diff-merges=first-parent`` is what makes a merge report its own change:
    without it git prints nothing for merge commits, so a lockfile introduced *by* a
    merge is never discovered at all — measured on a repository whose ``yarn.lock``
    sits at HEAD and was reported clean. ``--no-renames`` keeps rename
    detection from collapsing "package-lock deleted, npm-shrinkwrap added" into one
    record, which would hide a precedence handover, and keeps discovery working on a
    partial clone where similarity detection would need absent blobs.

    ``-z`` output is unquoted and NUL-separated, so it is split on NUL and nothing
    else: rewriting newlines as separators turned ``line\\nbreak/package-lock.json``
    into a file called ``break/package-lock.json``, which was then reported as
    unwalkable. The basename check rejects look-alikes such as
    ``sample-package-lock.json``, which the ``*name`` pathspec would match.
    """
    out = _git(repo, "log", "--all", "--full-history", "--diff-merges=first-parent",
               "--no-renames", "--format=", "--name-only", "-z",
               "--", *(f"*{name}" for name in basenames))
    wanted = set(basenames)
    names = {token[1:] if token.startswith("\n") else token
             for token in out.split("\0") if token.strip("\n")}
    return sorted(n for n in names if posixpath.basename(n) in wanted)


def discovered_lockfiles(repo: Path) -> tuple[list[str], list[str]]:
    """Lockfiles this tool can parse, and lockfiles it can only recognise.

    Both come from one history walk, because walking twice doubles the cost of
    the most expensive part of a scan.
    """
    found = _paths_with_basename(repo, (*PARSED_LOCKFILES, *FOREIGN_LOCKFILES))
    parsed = [p for p in found if posixpath.basename(p) in PARSED_LOCKFILES]
    foreign = [p for p in found if posixpath.basename(p) in FOREIGN_LOCKFILES]
    return parsed, foreign


def lockfile_paths(repo: Path) -> list[str]:
    """Every parseable lockfile path in this repository's history."""
    return discovered_lockfiles(repo)[0]


def _exists_at(repo: Path, sha: str, path: str) -> bool:
    """Whether ``path`` is present in one commit's tree.

    Asked of the tree rather than of the blob. ``cat-file -e <sha>:<path>`` needs the
    blob itself, so on a partial clone it either triggers a per-object fetch from the
    promisor remote or, with lazy fetching disabled, answers "missing" for a file that
    is plainly in the tree. Trees are never filtered out by ``blob:none``, so
    ``ls-tree`` answers from local data and cannot be wrong in that direction.
    """
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-z", "--name-only", sha, "--", path],
        capture_output=True, text=True, env=_git_env(GIT_NO_LAZY_FETCH="1"),
    )
    return result.returncode == 0 and bool(result.stdout.strip("\0"))


def _existed_during(repo: Path, path: str, query: WindowQuery,
                    refs: list[str], children: dict[str, list[str]],
                    present: dict[tuple[str, str], bool]) -> str | None:
    """A commit witnessing ``path`` in the tree while the window was open.

    A file's *contents* may be unreadable — a Yarn lockfile, a binary lock — but
    *when it was there* is always readable from git, and a file deleted before the
    window or added after it says nothing about the window.

    Every ref is asked separately and any one of them answering is enough: a
    deletion on ``main`` says nothing about a branch that still carries the file
    and is still built. Within a ref an interval ends at the first *descendant*
    that no longer has the file, so a sibling line cannot truncate it. The window
    test is the one exposures use, so a file present at the closing instant counts.
    """
    def here(sha: str) -> bool:
        key = (sha, path)
        if key not in present:
            present[key] = _exists_at(repo, sha, path)
        return present[key]

    for ref in refs:
        commits = _log_commits(repo, path, ref=ref)
        for i, commit in enumerate(commits):
            if not here(commit.sha):
                continue
            end: datetime | None = None
            forward = _descendants(children, commit.sha)
            for successor in commits[i + 1:]:
                if successor.sha in forward and not here(successor.sha):
                    end = successor.late
                    break
            if query.window_end is not None and commit.early > query.window_end:
                continue
            if end is not None and end <= query.window_start:
                continue
            return commit.sha
    return None



def _refs(repo: Path) -> list[str]:
    """HEAD first, then every branch head with a distinct tip."""
    out = _git(repo, "for-each-ref", "--format=%(refname) %(objectname)",
               "refs/heads", "refs/remotes")
    refs, seen_tips = ["HEAD"], {_git(repo, "rev-parse", "HEAD").strip()}
    for line in out.splitlines():
        name, tip = line.rsplit(" ", 1)
        if name.endswith("/HEAD") or tip in seen_tips:
            continue
        seen_tips.add(tip)
        refs.append(name)
    return refs


def _log_commits(repo: Path, path: str, *, ref: str | None = None,
                 all_refs: bool = False, also: tuple[str, ...] = ()) -> list[Commit]:
    """Commits touching one path, ancestors first, in git's topological order.

    Topological order (not date order) is what makes interval reasoning sound:
    a parent always precedes its descendants regardless of what the clocks said.

    ``--full-history`` is not optional. Git's default history simplification follows
    only one parent of a merge that is TREESAME to it, so a branch that pinned a
    malicious version and lost the merge conflict disappears from the log entirely —
    a repository whose CI built that branch reported exit 0. The flag costs
    extra commits, every one of which is judged on its own snapshot, so a superset
    can only improve the answer.

    ``also`` widens the log to commits that touched another path instead. It exists
    for precedence: removing a shrinkwrap puts the package-lock beside it back in
    charge without touching that file, so a log of the package-lock alone never
    sees the moment it started to matter.
    """
    args = ["log", "--topo-order", "--full-history", "--no-renames",
            "--format=%H|%aI|%cI"]
    if all_refs:
        args.append("--all")
    if ref:
        args.append(ref)
    args += ["--", path, *also]
    commits = []
    for line in _git(repo, *args).strip().splitlines():
        if not line:
            continue
        sha, author, committer = line.split("|")
        commits.append(Commit(sha, _parse_iso(author), _parse_iso(committer)))
    commits.reverse()
    return commits


def _commit_graph(repo: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Child and parent edges of the whole commit graph, read in one pass.

    Ancestry is asked thousands of times while pairing intervals, so it is
    answered in process from one ``rev-list`` rather than by spawning
    ``merge-base`` per pair — the difference between seconds and not finishing
    on a real repository.
    """
    children: dict[str, list[str]] = {}
    parents: dict[str, list[str]] = {}
    for line in _git(repo, "rev-list", "--all", "--parents").splitlines():
        shas = line.split()
        parents[shas[0]] = shas[1:]
        for parent in shas[1:]:
            children.setdefault(parent, []).append(shas[0])
    return children, parents


def _descendants(children: dict[str, list[str]], sha: str) -> set[str]:
    """Every commit reachable forward from `sha`, itself excluded."""
    seen: set[str] = set()
    stack = list(children.get(sha, ()))
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(children.get(current, ()))
    return seen


ABSENT = "absent"          # the commit genuinely has no lockfile there
UNREADABLE = "unreadable"  # we could not tell what it pinned
FOREIGN_DIALECT = "foreign-dialect"  # recognised format this tool does not parse yet


def _read_snapshot(repo: Path, sha: str, path: str,
                   finding: RepoFinding) -> LockfileModel | str:
    """Lockfile content at one commit, or why it is missing.

    Absence and unreadability must stay distinguishable: a commit that deleted
    the lockfile ends an exposure interval, while one we failed to read ends
    nothing and warns — otherwise a broken snapshot would silently close an
    interval and hide the exposure that followed it.
    """
    try:
        text = _git(repo, "show", f"{sha}:{path}")
    except GitError as e:
        message = str(e)
        if "does not exist" in message or "exists on disk, but not in" in message:
            return ABSENT
        finding.warnings.append(f"{path}@{sha[:8]}: snapshot unreadable ({message})")
        return UNREADABLE
    try:
        model = PARSED_LOCKFILES[posixpath.basename(path)](text)
    except Yarn1Lockfile:
        # Not lost evidence, so no warning: the tree is unread the way a foreign
        # lockfile is, and the caller decides whether it was unread inside the window.
        return FOREIGN_DIALECT
    except LockfileParseError as e:
        finding.warnings.append(f"{path}@{sha[:8]}: unreadable snapshot ({e})")
        return UNREADABLE
    if model.unread:
        # The readable rows are still judged; the warning keeps the repository from
        # being cleared on their strength alone.
        finding.warnings.append(
            f"{path}@{sha[:8]}: {len(model.unread)} package row(s) could not be read, "
            f"the first being {model.unread[0]}")
    return model


def _chain_for(model: LockfileModel, package: str, version: str) -> tuple[str, ...]:
    """Evidence chain for one concrete version: physical nesting when the
    instance is nested, name-level shortest chain otherwise."""
    instance = next(
        (p for p in model.instances_of(package) if p.version == version), None
    )
    if instance and instance.path.count("node_modules/") > 1:
        segments = [s.strip("/") for s in instance.path.split("node_modules/") if s]
        return tuple(segments)
    return tuple(model.chain_to(package) or (package,))


def _note_once(finding: RepoFinding, warned: set[str], message: str) -> None:
    """Record a diagnostic once per repo, however many refs re-encounter it."""
    if message not in warned:
        warned.add(message)
        finding.diagnostics.append(message)


def _scan_ref_chain(repo: Path, path: str, ref: str, chain: list[Commit],
                    query: WindowQuery, finding: RepoFinding,
                    seen: set[tuple], snapshots: dict[str, LockfileModel | str],
                    children: dict[str, list[str]], parents: dict[str, list[str]],
                    by_sha: dict[str, Commit], warned: set[str],
                    shadowed_by: str | None = None,
                    dialect_witness: dict[str, str] | None = None) -> None:
    """Judge one ref's lockfile history, ancestors first.

    An interval starts at the pinning commit and ends at the first *descendant*
    that no longer pins a named version — including one that deleted the
    lockfile. Successors that are merely later in topological order but not
    descendants (a sibling branch) do not close it: widening an interval
    over-reports, truncating one hides exposure.

    ``shadowed_by`` names a lockfile that takes precedence over this one; at any
    commit where it exists, this file is what npm ignored, so it testifies to
    nothing.
    """
    def snapshot(commit: Commit) -> LockfileModel | str:
        if commit.sha not in snapshots:
            snapshots[commit.sha] = _read_snapshot(repo, commit.sha, path, finding)
        return snapshots[commit.sha]

    def shadowed(sha: str) -> bool:
        """Whether the file taking precedence over this one exists at that commit."""
        return shadowed_by is not None and _exists_at(repo, sha, shadowed_by)

    for i, commit in enumerate(chain):
        if shadowed(commit.sha):
            continue
        model = snapshot(commit)
        if model is FOREIGN_DIALECT and dialect_witness is not None \
                and path not in dialect_witness:
            # The tree was in a dialect this tool does not parse. Like a foreign
            # lockfile, that keeps the repository from being cleared -- but only if
            # the dialect held the tree while the window was open: babel left Yarn 1
            # years before any incident this tool will be asked about, and denying
            # it an all-clear forever would punish the migration. The segment ends at
            # the first descendant whose snapshot is something else.
            until: datetime | None = None
            forward = _descendants(children, commit.sha)
            for successor in chain[i + 1:]:
                if successor.sha in forward and snapshot(successor) is not FOREIGN_DIALECT:
                    until = successor.late
                    break
            since = commit.early
            if not ((query.window_end is not None and since > query.window_end)
                    or (until is not None and until <= query.window_start)):
                dialect_witness[path] = commit.sha
        if isinstance(model, str):
            continue
        bad = model.versions_of(query.package) & query.malicious_versions
        if not bad:
            continue

        until: datetime | None = None
        forward = _descendants(children, commit.sha)
        for successor in chain[i + 1:]:
            if successor.sha not in forward:
                continue
            if shadowed(successor.sha):
                # npm stopped reading this file here, so the pin stopped mattering
                # here. Without this the interval stayed open and the report said
                # "still pinned" about a lockfile nothing installs.
                until = successor.late
                break
            later = snapshot(successor)
            if later is UNREADABLE or later is FOREIGN_DIALECT \
                    or (not isinstance(later, str) and later.unread):
                continue  # cannot claim the pin ended here
            if later is ABSENT or not (
                later.versions_of(query.package) & query.malicious_versions
            ):
                until = successor.late
                break
        since = commit.early

        # Half-open [since, until) against the inclusive window.
        if ((query.window_end is not None and since > query.window_end)
                or (until is not None and until <= query.window_start)):
            continue
        # Only a commit dated before its own parent is skewed; two commits on
        # parallel branches appearing out of date order in a topological listing
        # is ordinary branching, not a clock problem.
        for parent_sha in parents.get(commit.sha, ()):
            parent = by_sha.get(parent_sha)
            if parent is not None and commit.early < parent.early:
                _note_once(finding, warned,
                           f"{path}@{commit.sha[:8]}: commit predates its parent "
                           f"{parent_sha[:8]} (clock skew or rebase); interval "
                           "bounds are conservative")
        if commit.dates_diverge:
            _note_once(finding, warned,
                       f"{path}@{commit.sha[:8]}: author/committer dates diverge by "
                       ">48h (history likely rewritten); dates used conservatively")
        for version in sorted(bad):
            key = (path, commit.sha, version)
            if key in seen:
                continue
            seen.add(key)
            finding.exposures.append(Exposure(
                lockfile_path=path, version=version, since=since, until=until,
                commit=commit.sha, chain=_chain_for(model, query.package, version),
                evidence=f"interval:{ref}",
            ))


def scan_repo(repo: Path, query: WindowQuery,
              coverage_cache: CoverageCache
              | None = None, trusted_url: str | None = None,
              authenticate: bool = True) -> RepoFinding:
    """Judge one repository across every ref; see the module docstring for the model.

    ``coverage_cache`` lets a caller that asks the same repository about many
    packages pay for the remote's branch list once; a lone call needs none.
    """
    finding = RepoFinding(repo=repo)
    warned: set[str] = set()
    try:
        truncated, observed = incomplete_history(repo, coverage_cache, trusted_url,
                                                 authenticate)
        finding.incomplete.extend(truncated)
        finding.diagnostics.extend(observed)
        paths, foreign = discovered_lockfiles(repo)
        refs = _refs(repo)
        children, parents = _commit_graph(repo) if paths or foreign else ({}, {})
        # A foreign lockfile only says something about the window if it was there
        # during it: holding one committed years earlier against a project denied
        # an all-clear forever.
        present: dict[tuple[str, str], bool] = {}
        live_foreign = {
            path: witness for path in foreign
            if (witness := _existed_during(repo, path, query, refs, children, present))
        }
    except GitError as e:
        finding.warnings.append(str(e))
        return finding

    for path, witness in live_foreign.items():
        tool = FOREIGN_LOCKFILES[posixpath.basename(path)]
        finding.unread_trees.append(UnreadTree(
            path=path,
            reason=f"{path}: {tool} lockfiles are not parsed yet, so the versions this "
                   "tree installed were not judged",
            commit=witness,
        ))

    for path in paths:
        finding.lockfiles_seen += 1
        seen: set[tuple] = set()
        snapshots: dict[str, LockfileModel | str] = {}
        by_sha: dict[str, Commit] = {}
        dialect_witness: dict[str, str] = {}
        any_history = False
        # npm ignores package-lock.json entirely when a shrinkwrap sits beside it,
        # so judging both independently would invent an exposure from a file npm
        # never read. pnpm-lock.yaml is outside this: it is another tool's install.
        shadowed_by = None
        if posixpath.basename(path) == "package-lock.json":
            sibling = posixpath.join(posixpath.dirname(path), "npm-shrinkwrap.json")
            shadowed_by = sibling if sibling in paths else None

        for ref in refs:
            try:
                # Reuse the log the coverage pass already read, unless precedence
                # needs the wider one: a git log per file per ref is what a monorepo
                # scan spends its time on.
                chain = _log_commits(repo, path, ref=ref,
                                     also=(shadowed_by,) if shadowed_by else ())
            except GitError as e:
                finding.warnings.append(f"{path}@{ref}: {e}")
                continue
            if chain:
                any_history = True
                by_sha.update({c.sha: c for c in chain})
                _scan_ref_chain(repo, path, ref, chain, query, finding, seen,
                                snapshots, children, parents, by_sha, warned,
                                shadowed_by=shadowed_by,
                                dialect_witness=dialect_witness)

        if path in dialect_witness:
            finding.unread_trees.append(UnreadTree(
                path=path,
                reason=f"{path}: Yarn 1 lockfiles are not parsed yet, so the versions "
                       "this tree installed while it was Yarn 1 were not judged",
                commit=dialect_witness[path],
            ))
        if not any_history:
            finding.warnings.append(
                f"{path}: discovered in refs but no walkable history (evidence unreadable)"
            )
    return finding
