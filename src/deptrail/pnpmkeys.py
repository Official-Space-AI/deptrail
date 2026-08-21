"""Split a pnpm lockfile package key into a package name and an installed version.

A pnpm lockfile names each installed package by a *key* of its ``packages:`` mapping,
and the key's grammar changed twice: ``/chalk/5.6.1`` (lockfileVersion 5), ``/chalk@5.6.1``
(6), ``chalk@5.6.1`` (9). Peer-dependency context, patch hashes, registry hosts, git
URLs and local paths are folded into the same string. Getting the split wrong does not
fail loudly: it renames a package, and a renamed package is either a compromised version
this tool fails to find or a clean one it accuses.

Everything here is measured rather than guessed. The rules were derived from, and then
run back over, 3,352 real lockfiles holding 2,694,992 package-key rows -- every
``lockfileVersion`` that exists in the wild (``5`` as a bare integer, ``5.1``, ``5.2``,
``5.3``, ``5.3-inlineSpecifiers``, ``5.4``, ``6.0``, ``6.1``, ``9.0``). Four oracles that
are not the key itself agreed on every split: 4.5 million dependency edges, 112,526
tarball filenames, 74,562 key-versus-body comparisons and 56 live registry probes. Four
deliberately broken variants of the rules were caught by those same oracles, so the
agreement is load-bearing rather than a blind pass.

Three facts drive the design, each of which a first attempt got wrong:

* **The body outranks the key in 5.x and 6.x.** An entry carrying ``name:`` and
  ``version:`` is pnpm's own ``nameVerFromPkgSnapshot`` answer, and a host-prefixed key
  can name an *alias* -- ``example.pkgs.visualstudio.com/@scope/testDep/2.1.0`` is really
  ``pad-left 2.1.0``. Reading the key over the body renamed that package.
* **A 9.0 ``snapshots:`` key carries no version of its own.** The version lives in the
  same document's ``packages:`` entry for the key's *base* (the key with its
  parenthesised suffix stripped). Reading it from the key instead handed back a URL as
  the version of ``vue`` in 86 rows across 46 repositories.
* **Semver build metadata never appears.** Zero of 2,694,992 keys carry ``+build``.
  Every ``+`` in a key is a peer joiner, a scope separator or a port; a rule that trims
  at ``+`` corrupts 38,744 keys.

A key that cannot be read is returned with status ``unknown`` and a reason, never
dropped and never guessed: dropping is how a compromised package goes unreported, and a
caller that sees ``unknown`` knows to leave the repository INDETERMINATE.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .lockfile import NOT_NPM, NPM, OTHER_REGISTRY, SOURCE, LockfileParseError

# Semver as pnpm writes it. Build metadata is allowed by the grammar and absent from every
# real key; see the module docstring for why that matters. Matched with ``fullmatch``: a
# ``$`` alone accepts a trailing newline, and a quoted key can carry an escaped one.
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_NAME = re.compile(r"^(?:@[^/@()\s]+/)?[^/@()\s]+$")
# A registry host as pnpm's encode-registry writes it: a port's ':' becomes '+'.
_HOST = re.compile(r"[A-Za-z0-9._-]+(\+[0-9]+)?")
_PROTOCOLS = ("file:", "link:", "git+", "git:", "http:", "https:", "workspace:",
              "npm:", "jsr:", "catalog:")
_GIT_HOSTS = ("github.com/", "gitlab.com/", "bitbucket.org/", "git.sr.ht/",
              "codeload.github.com/")
_PROTOCOL = re.compile(r"^([a-z][a-z0-9+.-]*):(.*)$")

# What a row is, from the point of view of "was this compromised version installed". The
# four that describe a readable row are the model's ``InstalledPackage.origin`` vocabulary
# and are defined there; ``unknown`` never becomes a package, so it lives here.
UNKNOWN = "unknown"              # unreadable; the caller must not call the tree clean


@dataclass(frozen=True)
class KeyRecord:
    """One package-key row, split.

    ``status`` is the field a caller dispatches on; ``reason`` explains an ``unknown`` or
    ``not-npm``. ``version_from`` records whether the version was read off the key, off
    the entry body, or off the ``packages:`` body a 9.0 snapshot points at -- kept because
    the two disagree on 5.x aliases and a report should be able to say which it trusted.
    ``peers`` are the parenthesised groups verbatim: context, never identity.
    """

    status: str
    name: str | None
    version: str | None
    version_from: str | None
    origin: str | None
    patched: bool = False
    peers: tuple[str, ...] = ()
    reason: str = ""


class UnsupportedLockfileVersion(LockfileParseError):
    """A ``lockfileVersion`` this module has no grammar for.

    A ``LockfileParseError`` because that is the condition: a lockfile in a format this
    tool does not understand. ``history.py`` turns that into an unreadable snapshot and
    an INDETERMINATE repository; as a bare ``ValueError`` it walked past that handler
    and took the scan down with it.
    """


def band_of(lockfile_version: object) -> str:
    """``v5``, ``v6`` or ``v9`` from whatever ``lockfileVersion`` the document carries.

    The value may be an integer or a string, and the strings include
    ``5.3-inlineSpecifiers``. An allow-list of the common literals refused real files; the
    first character does not. ``7`` and ``8`` were never written (pnpm 7 wrote 5.4, pnpm 8
    wrote 6.0).
    """
    text = str(lockfile_version).strip()
    if text.startswith("5"):
        return "v5"
    if text.startswith("6"):
        return "v6"
    if text.startswith("9"):
        return "v9"
    raise UnsupportedLockfileVersion(f"unsupported lockfileVersion {lockfile_version!r}")


def split_key(lockfile_version: object, key: str, entry: object,
              packages: object = None) -> KeyRecord:
    """Split one ``packages:`` or ``snapshots:`` key.

    ``entry`` is the key's own mapping body. ``packages`` is the document's whole
    ``packages:`` mapping, needed only for 9.0, where a ``snapshots:`` row's version
    lives in ``packages[base]``.
    """
    band = band_of(lockfile_version)
    if band == "v9":
        return _split_v9(key, entry, packages)
    return _split_v5v6(key, entry)


def suffix_groups(key: str) -> tuple[str, list[str]]:
    """The key without its trailing ``(...)`` groups, and those groups in source order.

    A backward balanced scan, which is what pnpm's own ``indexOfPeersSuffix`` does, so a
    ``(`` inside a URL earlier in the key is left alone. ``key.split("(")[0]`` happens to
    work on 6.x and breaks on 9.0, where URLs carry parentheses.
    """
    end, groups = len(key), []
    while end > 0 and key[end - 1] == ")":
        depth, start = 0, end - 1
        while start >= 0:
            if key[start] == ")":
                depth += 1
            elif key[start] == "(":
                depth -= 1
                if depth == 0:
                    break
            start -= 1
        if start < 0:
            raise _Unreadable(f"unbalanced parenthesis: {key!r}")
        groups.append(key[start + 1:end - 1])
        end = start
    groups.reverse()
    return key[:end], groups


class _Unreadable(Exception):
    """Internal: the key could not be read; becomes ``UNKNOWN`` at the boundary."""


def _host_split(base: str) -> tuple[str | None, str] | None:
    """``(host, rest)`` for a registry-shaped key, ``None`` for a location."""
    if base.startswith("/"):
        return None, base[1:]
    if base.startswith(_PROTOCOLS):
        return None
    host, separator, rest = base.partition("/")
    if not separator or not _HOST.fullmatch(host):
        return None
    # No "must contain a dot" rule. pnpm's own `dependency-path.parse` has none, and
    # `encode-registry` writes `http://verdaccio:4873` as `verdaccio+4873` -- a Docker
    # service name, ordinary in CI. An earlier version required a dot to keep a
    # hypothetical `chalk/5.6.1` from reading as host `chalk`; that shape is one pnpm
    # never writes, and the guard it justified demoted every dotless private registry to
    # a tarball of unknown provenance. Two reviews found it independently.
    return host, rest


def _parse_v5_identity(key: str) -> tuple[str, str, str | None] | None:
    """``/[@scope/]name/version[_suffix]`` -> ``(name, version, host)`` or ``None``.

    Segment on ``/`` first and cut the version at the *first* ``_``: semver cannot contain
    an underscore, but a name can (``string_decoder``), and a stacked suffix has several.
    """
    base, _ = suffix_groups(key)
    split = _host_split(base)
    if split is None:
        return None
    host, rest = split
    parts = rest.split("/")
    if parts[0].startswith("@"):
        if len(parts) < 3:
            return None
        name, tail = parts[0] + "/" + parts[1], "/".join(parts[2:])
    else:
        if len(parts) < 2:
            return None
        name, tail = parts[0], "/".join(parts[1:])
    version = tail.split("_", 1)[0]
    if not _SEMVER.fullmatch(version) or not _NAME.fullmatch(name):
        return None
    return name, version, host


def _parse_v6_identity(key: str) -> tuple[str, str, str | None] | None:
    """``/[@scope/]name@version[suffix]`` -> ``(name, version, host)`` or ``None``.

    The name/version ``@`` is found structurally: for a scoped name it is the first ``@``
    *after* the ``/``. ``rsplit("@")`` renamed 23 % of suffixed keys by cutting inside the
    peer group. 6.x still writes 5.x's ``_`` peer suffix, so the version is cut there too.
    """
    base, _ = suffix_groups(key)
    split = _host_split(base)
    if split is None:
        return None
    host, rest = split
    if rest.startswith("@"):
        slash = rest.find("/")
        if slash < 1:
            return None
        at = rest.find("@", slash)
    else:
        at = rest.find("@")
    if at <= 0:
        return None
    name, tail = rest[:at], rest[at + 1:]
    version = tail.split("_", 1)[0]
    if not _SEMVER.fullmatch(version) or not _NAME.fullmatch(name):
        return None
    return name, version, host


def _flag(value: object) -> bool:
    """A YAML boolean as the reader delivers it -- a string, so ``"false"`` is false."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "on")
    return bool(value)


def _origin_of(key: str, entry: dict) -> str | None:
    resolution = entry.get("resolution") or {}
    if not isinstance(resolution, dict):
        resolution = {}
    kind, tarball = resolution.get("type"), str(resolution.get("tarball") or "")
    if kind == "directory" or resolution.get("directory") is not None:
        return "local-dir"
    if kind == "git" or resolution.get("commit") is not None:
        return "git"
    if key.startswith(_GIT_HOSTS) or "codeload.github.com" in tarball:
        return "git"
    if tarball.startswith("file:") or key.startswith("file:"):
        return "local-tarball"
    if tarball.startswith(("http://", "https://")) or key.startswith(("http://", "https://")):
        return "remote-tarball"
    return None


def _split_v5v6(key: str, entry: object) -> KeyRecord:
    """5.x and 6.x share one tail: the body outranks the key.

    Either band's document can carry the other band's key shape (21 rows of 5.x keys
    inside 6.0 files, each with an ``id:`` field), and the two shapes are mutually
    unambiguous, so both parsers are tried.
    """
    body = entry if isinstance(entry, dict) else {}
    try:
        identity = _parse_v5_identity(key) or _parse_v6_identity(key)
        _, groups = suffix_groups(key)
    except _Unreadable as error:
        return KeyRecord(UNKNOWN, None, None, None, None, reason=str(error))
    patched = _flag(body.get("patched")) or any(g.startswith("patch_hash=") for g in groups)
    peers = tuple(g for g in groups if not g.startswith("patch_hash="))
    body_name, body_version = body.get("name"), body.get("version")

    def record(status, name, version, version_from, origin, reason=""):
        return KeyRecord(status, name, version, version_from, origin, patched, peers, reason)

    # The body outranks the key, so the body has to be something worth outranking it
    # with. A `version:` that is a mapping or a list is not a version; `str()` of it was
    # being written into the record, and a record with `"{'x': 1}"` where a version
    # belongs never matches an advisory -- a clean verdict manufactured from garbage.
    # A blank one is the same failure with less to look at: `version: ''` outranked
    # the key and left a row whose version is the empty string.
    for label, value in (("name", body_name), ("version", body_version)):
        if value is not None and not isinstance(value, str):
            return record(UNKNOWN, None, None, None, None,
                          f"body {label} is a {type(value).__name__}, not a string")
        if isinstance(value, str) and not value.strip():
            return record(UNKNOWN, None, None, None, None, f"body {label} is blank")
    # A body name has to be a name pnpm could have installed: `name: not a name at all`
    # became a registry row nothing matches, and `name: (root)` would have merged the
    # package's edges into the project's.
    if body_name is not None and not _NAME.fullmatch(body_name):
        return record(UNKNOWN, None, None, None, None, f"body name {body_name!r} is not a name")

    if identity is not None:
        key_name, key_version, host = identity
        origin = "registry" if host is None else "registry-host"
        if body_name is None:
            return record(NPM, key_name, key_version, "key", origin)
        if body_version is None:
            return record(UNKNOWN, str(body_name), None, None, origin,
                          "body names the package but records no version")
        # To outrank a version that is already in the key, the body's has to be one.
        # For a git or tarball row below there is no key version to protect, and pnpm
        # records whatever the checkout said -- `denolib/camelcase#aeb6b15f...` in
        # its own fixtures -- so there it is kept as written.
        if not _SEMVER.fullmatch(body_version):
            return record(UNKNOWN, None, None, None, origin,
                          f"body version {body_version!r} is not a version")
        return record(NPM, str(body_name), str(body_version), "body", origin)

    origin = _origin_of(key, body)
    if origin == "local-dir":
        return record(NOT_NPM, str(body_name) if body_name is not None else None, None,
                      None, "local-dir", "local directory link, not a published artifact")
    if body_name is None:
        return record(UNKNOWN, None, None, None, origin,
                      "key is not a registry identity and the body has no name")
    if body_version is None:
        return record(UNKNOWN, str(body_name), None, None, origin,
                      "body names the package but records no version")
    return record(SOURCE, str(body_name), str(body_version), "body", origin or "unknown")


def _split_v9(key: str, entry: object, packages: object) -> KeyRecord:
    """9.0: ``name@version[(peer)...]``, with the version of a snapshot in ``packages``.

    A leading ``/`` is a 5.x or 6.x key in a document that claims 9.0. It is refused
    here, per key, and never guessed at: a document can genuinely mix both shapes
    (measured: 18 + 2), so re-dispatching per key would misparse the majority. The
    caller that holds the whole document decides whether *every* key refused this way,
    which is the only case where re-reading the document under the other grammar is
    sound.
    """
    body = entry if isinstance(entry, dict) else {}
    table = packages if isinstance(packages, dict) else {}
    if key.startswith("/"):
        return KeyRecord(UNKNOWN, None, None, None, None,
                         reason="v5/v6-style key in a document declaring lockfileVersion 9.0")
    try:
        base, groups = suffix_groups(key)
    except _Unreadable as error:
        return KeyRecord(UNKNOWN, None, None, None, None, reason=str(error))
    # The first '@' after index 0: a scoped name starts with one, and the version's '@'
    # is the next. Git URLs carry '@' later on (`git@github.com:`), which is why the
    # last one is wrong.
    at = base.find("@", 1)
    if at < 1:
        return KeyRecord(UNKNOWN, None, None, None, None,
                         reason=f"no name@version separator: {key!r}")
    name, key_version = base[:at], base[at + 1:]
    if not key_version or not _NAME.fullmatch(name):
        return KeyRecord(UNKNOWN, None, None, None, None, reason=f"implausible key: {key!r}")
    patched = any(g.startswith("patch_hash=") for g in groups)
    peers = tuple(g for g in groups if not g.startswith("patch_hash="))

    package_body = table.get(base)
    package_body = package_body if isinstance(package_body, dict) else {}
    body_version = body.get("version") or package_body.get("version")
    if body_version is not None and not isinstance(body_version, str):
        return KeyRecord(UNKNOWN, name, None, None, None, patched, peers,
                         f"recorded version is a {type(body_version).__name__}, not a string")
    if isinstance(body_version, str) and not body_version.strip():
        return KeyRecord(UNKNOWN, name, None, None, None, patched, peers,
                         "recorded version is blank")
    # A recorded version may outrank a version that is in the key only if it is one;
    # a git or tarball row keeps whatever pnpm recorded (see `_split_v5v6`).
    outranks_badly = body_version is not None and not _SEMVER.fullmatch(body_version)
    resolution = body.get("resolution") or package_body.get("resolution") or {}
    if not isinstance(resolution, dict):
        resolution = {}
    kind, tarball = resolution.get("type"), str(resolution.get("tarball") or "")

    def record(status, version, version_from, origin, reason=""):
        return KeyRecord(status, name, version, version_from, origin, patched, peers, reason)

    def versioned():
        return (str(body_version), "packages-body") if body_version else (key_version, "key")

    if _SEMVER.fullmatch(key_version):
        if outranks_badly:
            return record(UNKNOWN, None, None, None,
                          f"recorded version {body_version!r} is not a version")
        version, source = versioned()
        if name.startswith("@jsr/") or "npm.jsr.io" in tarball:
            return record(OTHER_REGISTRY, version, source, "jsr",
                          "JSR namespace, not an npmjs package")
        return record(NPM, version, source, "registry")
    if key_version.startswith("file:"):
        is_tarball = tarball.endswith(".tgz") or key_version.endswith(".tgz")
        if kind == "directory" or (not is_tarball and body_version is None):
            return record(NOT_NPM, None, None, "local-dir",
                          "local directory link, not a published artifact")
        if body_version is None:
            return record(UNKNOWN, None, None, "local-tarball",
                          "local tarball with no version recorded")
        return record(SOURCE, str(body_version), "packages-body", "local-tarball")
    if key_version.startswith(("http://", "https://", "git+", "git:")) or kind == "git":
        origin = ("git" if kind == "git" or key_version.startswith(("git+", "git:"))
                  or "codeload.github.com" in key_version else "remote-tarball")
        if body_version is None:
            return record(UNKNOWN, None, None, origin,
                          f"no version recorded for a {origin} dependency")
        return record(SOURCE, str(body_version), "packages-body", origin)
    protocol = _PROTOCOL.match(key_version)
    if protocol:
        alias, rest = protocol.group(1), protocol.group(2)
        if alias == "runtime":
            version, source = (str(body_version), "packages-body") if body_version else (rest, "key")
            return record(NOT_NPM, version, source, "runtime", "JS runtime, not an npm package")
        if _SEMVER.fullmatch(rest):
            if outranks_badly:
                return record(UNKNOWN, None, None, None,
                              f"recorded version {body_version!r} is not a version")
            version, source = (str(body_version), "packages-body") if body_version else (rest, "key")
            return record(NPM if alias == "npmjs" else OTHER_REGISTRY, version, source,
                          "named-registry:" + alias,
                          "" if alias == "npmjs" else f"resolved from named registry {alias!r}")
        return record(UNKNOWN, None, None, "protocol:" + alias,
                      f"unrecognised protocol version {key_version!r}")
    if body_version:
        return record(SOURCE, str(body_version), "packages-body", "unknown")
    return record(UNKNOWN, None, None, None,
                  f"version part is neither semver nor a recognised protocol: {key_version!r}")
