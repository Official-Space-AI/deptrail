"""Read a Yarn Berry ``yarn.lock`` into the same ``LockfileModel`` the other parsers build.

Berry (Yarn 2 and later) writes YAML, and unlike pnpm it separates *request* from
*answer* inside the file: each mapping key is a comma-joined list of descriptors (what
some package asked for -- ``chalk@npm:^5.0.0``), and the entry's ``resolution`` is the
one locator that answered them (``chalk@npm:5.6.1``). Identity therefore comes from
``resolution`` and never from the key, which settles aliasing for free: the descriptor
``@babel-baseline/cli@npm:@babel/cli@7.27.1`` resolves to ``@babel/cli@npm:7.27.1``,
and the row is named ``@babel/cli``.

Every choice below was measured on 2,186 real Berry lockfiles (4,504,922 entries,
10,658,523 edges) -- every ``__metadata`` version 1 through 10, taken from the full
histories of ``yarnpkg/berry``, ``babel/babel`` and ``jestjs/jest`` plus the corpus
snapshots; the vendored YAML reader read all of them (0 refusals):

* **The locator protocol decides what a row is.** ``npm:`` (4,266,936) is a registry
  row whose installed version is the entry's ``version:``. ``patch:`` (13,305) wraps
  another locator, URL-encoded before the ``#``; the inner protocol is ``npm:`` in all
  but 3 rows, which wrap another ``patch:``, so the wrapper is unwrapped until it is
  not one. ``https:`` and ``git+https:`` (1,063) are ``source``. ``workspace:``,
  ``link:`` and ``portal:`` (212,275) are the project itself: no row, and their
  ``dependencies`` are the project's roots -- the lockfile folds dev dependencies into
  ``dependencies``, so nothing is lost by reading just that block. ``condition:``
  (11,302) is a switch between variants that are themselves rows; it contributes its
  edges and no row.
* **An edge names its request; the descriptor index answers it.** ``dependencies``
  maps a name to a range; the entry that answered it is the one whose key contains
  ``name@range`` (metadata 8 and later write the ``npm:`` protocol into the range;
  earlier versions write it bare, so both spellings are tried). The 11,834 aliased
  edges resolve through the same index to the name the resolution carries.
* **``version:`` is present on 4,504,920 of 4,504,922 entries.** The two without are
  refused into ``unread`` rather than guessed.
* **41 resolutions carry no protocol at all** -- early Berry wrote a GitHub shorthand,
  ``left-pad@left-pad/left-pad#commit:a1b2c3``, whose reference holds ``/`` and ``#``
  where a protocol token cannot. Those are ``source`` rows, like any git checkout.
* **Berry needs the truncation guard pnpm needed.** YAML is prefix-valid, so a file
  cut at an entry boundary still parses with the surviving entries' edges pointing at
  nothing. In a complete file every edge is answered: 10,600,996 of 10,658,523 by the
  descriptor index, and all 57,527 others -- overridden ranges, ``catalog:``,
  ``link:``, ``portal:``, ``condition:`` ranges -- by an entry answering to the name.
  An edge neither answers is therefore unread evidence, and the check flags zero of
  the 2,186 real files.

A row that cannot be read lands in ``LockfileModel.unread`` with its reason, never
dropped: a dropped row is a version the report calls absent.
"""
from __future__ import annotations

import urllib.parse

from .lockfile import (NOT_NPM, NPM, ROOT, SOURCE, InstalledPackage, LockfileModel,
                       LockfileParseError)
from .yamlsubset import load

# Locator protocols that mean "the project itself, linked into place": their entries
# describe workspaces, not installed artifacts, and their dependencies are the
# project's direct dependencies.
_PROJECT = ("workspace", "link", "portal")


def parse_yarn_berry_lockfile(text: str) -> LockfileModel:
    """The single Berry document in ``text``, as a model.

    Raises ``LockfileParseError`` when the text is not a Berry lockfile at all: not
    YAML in the subset, not a mapping, no ``__metadata`` block. A Yarn 1 file has no
    ``__metadata`` and is refused here; the caller that can see the filename decides
    what a Yarn 1 tree becomes.
    """
    document = load(text)
    if not isinstance(document, dict):
        raise LockfileParseError("a Berry lockfile is a mapping")
    metadata = document.get("__metadata")
    if not isinstance(metadata, dict):
        raise LockfileParseError("no __metadata block, so not a Berry lockfile")

    entries: list[tuple[str, dict]] = []
    unread: list[str] = []
    for key, entry in document.items():
        if key == "__metadata":
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("resolution"), str):
            unread.append(f"{key}: entry carries no resolution")
            continue
        entries.append((key, entry))

    # descriptor -> the resolution that answered it, for edge resolution below.
    answered: dict[str, str] = {}
    for key, entry in entries:
        for descriptor in key.split(","):
            answered[descriptor.strip()] = entry["resolution"]

    installed: list[InstalledPackage] = []
    declared: dict[str, set[str]] = {ROOT: set()}
    root_deps: set[str] = set()
    for key, entry in entries:
        resolution = entry["resolution"]
        name, protocol, reference = _locator(resolution)
        if name is not None and protocol is not None and ("/" in protocol or "#" in protocol):
            protocol = "github-shorthand"  # early Berry: name@owner/repo#commit:sha
        if name is None:
            shorthand = _github_shorthand(resolution)
            if shorthand is None:
                unread.append(f"{key}: resolution {resolution!r} is not a locator")
                continue
            name, protocol = shorthand, "github-shorthand"
        while protocol == "patch":
            # ``chalk@patch:chalk@npm%3A5.6.1#...``: the artifact is the inner locator
            # with a patch applied; the installed version is still the entry's.
            name, protocol, reference = _locator(urllib.parse.unquote(reference.split("#", 1)[0]))
            if name is None:
                break
        if name is None:
            unread.append(f"{key}: resolution {resolution!r} wraps no locator")
            continue

        edges = _edges(entry, answered)
        declared.setdefault(name, set()).update(edges)
        if protocol in _PROJECT:
            root_deps |= edges
            continue
        if protocol == "condition":
            # A switch between variants that are rows of their own; the switch itself
            # is not an artifact.
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version.strip():
            unread.append(f"{key}: entry records no version")
            continue
        if protocol == "npm":
            origin = NPM
        elif protocol in ("https", "http", "git+https", "git+ssh", "git", "github-shorthand"):
            origin = SOURCE
        elif protocol == "npm-runtime":  # never observed; kept explicit for the reader
            origin = NOT_NPM
        else:
            unread.append(f"{key}: resolution protocol {protocol!r} is not one this reads")
            continue
        installed.append(InstalledPackage(name=name, version=version,
                                          path=resolution, origin=origin))

    declared[ROOT] |= root_deps
    # Only when nothing else already keeps this snapshot from reading clean, as in
    # the pnpm reader: with unread rows the walker warns and holds intervals open
    # regardless, and a missing answer is then likelier one of those rows.
    if not unread:
        unread += _edges_without_entries(entries, answered, declared)
    return LockfileModel(
        lockfile_version=str(metadata.get("version")),
        root_name="(unnamed)",
        root_deps=root_deps,
        packages=installed,
        declared=declared,
        unread=unread,
    )


def _github_shorthand(text: str) -> str | None:
    """``left-pad@left-pad/left-pad#commit:a1b2c3`` -> ``left-pad``; None when the text
    is not that shape. 41 real resolutions have no protocol, and every one of them is
    this: a repository path where a protocol would stand."""
    at = text.find("@", 1)
    if at < 1 or "/" not in text[at + 1:]:
        return None
    return text[:at]


def _edges_without_entries(entries: list[tuple[str, dict]], answered: dict[str, str],
                           declared: dict[str, set[str]]) -> list[str]:
    """Edges no entry answers: unread evidence, not a clean tree.

    YAML is prefix-valid where JSON is not, so a ``yarn.lock`` truncated at an entry
    boundary still parses -- the surviving entries still declare the dependency, and
    the entry that answered it is gone. In a complete file every edge is answered by
    the descriptor index or by an entry of that name (measured; the docstring has the
    split), so an edge with neither is a hole where evidence stood, and reading it as
    "not installed" called the tree clean and closed exposure intervals.
    """
    names = set(declared)
    missing: dict[tuple[str, str], None] = {}
    for _key, entry in entries:
        dependencies = entry.get("dependencies")
        if not isinstance(dependencies, dict):
            continue
        for declared_name, range_ in dependencies.items():
            declared_name = str(declared_name)
            if not isinstance(range_, str):
                continue
            if (f"{declared_name}@{range_}" in answered
                    or f"{declared_name}@npm:{range_}" in answered
                    or declared_name in names):
                continue
            missing.setdefault((declared_name, range_))
    return [f"{name}: the document resolves it to {range_!r} and holds no entry for it"
            for name, range_ in sorted(missing)]


def _locator(text: str) -> tuple[str | None, str | None, str]:
    """``name@protocol:reference`` -> its three parts, or Nones.

    The name may be scoped, so the separating ``@`` is the first one after position
    zero; the protocol ends at the first ``:`` of the remainder. A locator always has
    a protocol -- 41 bare resolutions were measured, all in hand-rolled files, and the
    caller refuses them.
    """
    at = text.find("@", 1)
    if at < 1:
        return None, None, ""
    name, rest = text[:at], text[at + 1:]
    colon = rest.find(":")
    if colon < 1:
        return None, None, ""
    return name, rest[:colon], rest[colon + 1:]


def _edges(entry: dict, answered: dict[str, str]) -> set[str]:
    """The names an entry's dependencies resolve to.

    The range is looked up in the descriptor index under both spellings (metadata 8+
    writes ``npm:`` into ranges, earlier versions write them bare); an aliased edge
    (``execa: npm:safe-execa@^0.1.2``) thereby lands on the resolution that answered
    it and takes its name. A range no descriptor answers keeps the declared name.
    """
    names: set[str] = set()
    dependencies = entry.get("dependencies")
    if not isinstance(dependencies, dict):
        return names
    for declared_name, range_ in dependencies.items():
        declared_name = str(declared_name)
        if not isinstance(range_, str):
            names.add(declared_name)
            continue
        resolution = (answered.get(f"{declared_name}@{range_}")
                      or answered.get(f"{declared_name}@npm:{range_}"))
        if resolution is None:
            names.add(declared_name)
            continue
        name, _protocol, _reference = _locator(resolution)
        names.add(name if name is not None else declared_name)
    return names
