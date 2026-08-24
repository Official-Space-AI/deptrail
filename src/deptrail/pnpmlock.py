"""Read a ``pnpm-lock.yaml`` into the same ``LockfileModel`` the npm parser builds.

The key grammar is ``pnpmkeys``' problem; this module's problem is the document around
the keys -- which section the rows live in, which section the edges live in, what the
project itself depends on, and what to do with a row that would not read. Every choice
below was measured on 6,395 real documents (6,415 files, every ``lockfileVersion`` pnpm
has written), because the shapes are not what the format's description suggests:

* **A file can hold two documents.** pnpm 12 writes its own pinned install (the
  ``@pnpm/exe.*`` binaries and a ``node@runtime:`` row) as a document ahead of the
  project's; 13 of 6,415 files do this. Both were installed on the machine that ran
  ``pnpm install``, so both are read and merged into one model.
* **Most documents have no ``importers:``.** 4,561 single-project 5.x documents put the
  importer's blocks (``dependencies``, ``devDependencies``, ``specifiers``) at the top
  level, and one 9.0 document does too. When ``importers:`` is absent the document *is*
  the importer.
* **9.0 keeps rows and edges in different sections.** ``packages:`` has one entry per
  (name, version) and no dependencies; ``snapshots:`` has one entry per peer variant and
  holds the dependencies. Rows come from ``packages:`` (so a key that lives only there
  is not missed -- the mixed fixture keeps its two legacy keys there), edges from both.
  0 of 468,830 snapshot bases are missing from ``packages:``; the 64 ``packages:``
  entries that do carry edges are read as well.
* **The header can lie.** Two documents declare ``9.0`` over 5.x/6.x-shaped keys. A
  document whose every key the 9.0 grammar refuses, and some key the 5.x/6.x grammar
  reads, is re-read under the latter; a document with even one 9.0 key is not, because
  genuinely mixed documents exist (18 + 2) and re-reading those would misparse the 18.
  The decision is made here, on the whole document, and never per key.
* **An edge may name one package and point at another.** 122,993 of 7,629,683 edges
  (aliases, ``execa: /safe-execa@0.1.2``; git dependencies, ``ci-info:
  github.com/watson/ci-info/f43f6a1c...``) carry a dep-path rather than a version. A
  dep-path is a key of the same document, so an edge whose value is a key is resolved
  to the name that key installs; every other edge keeps the name it was declared under.
  Without this the name-level graph has edges to packages that are not in it.

What a row becomes: a readable row with a version is an ``InstalledPackage`` whose
``origin`` is the key's status (``npm``, ``other-registry``, ``source``, ``not-npm``); a
readable row with a name and no version (a local directory link) contributes its edges
under its name and no row; a row with neither name nor version contributes nothing (18
rows corpus-wide, all vendored scanner fixtures); an unreadable row goes to
``LockfileModel.unread`` with its reason, never dropped -- a dropped row is a version the
report calls absent.
"""
from __future__ import annotations

from .lockfile import ROOT, InstalledPackage, LockfileModel, LockfileParseError
from .pnpmkeys import UNKNOWN, KeyRecord, band_of, split_key, suffix_groups
from .yamlsubset import load_documents

# Blocks of an importer whose keys are names the project depends on. The last two are
# pnpm 12's, where the package manager pins itself and its config dependencies, and they
# were installed like anything else. 5.x's ``specifiers`` block is not read: it names the
# same packages as the resolved blocks, but by their alias names, and an alias name in
# ``root_deps`` ends a chain at a package the project never declared.
_IMPORTER_BLOCKS = ("dependencies", "devDependencies", "optionalDependencies",
                    "packageManagerDependencies", "configDependencies")
# Blocks of a package entry whose keys are names the package depends on. Peer
# dependencies are constraints on the parent, not edges to an installed instance.
_PACKAGE_BLOCKS = ("dependencies", "optionalDependencies")
# 5.x and 6.x share one grammar in pnpmkeys, so any literal from either band selects it;
# this is the one used to re-read a document whose 9.0 header lies about its keys.
_LEGACY_GRAMMAR = "6.0"


def parse_pnpm_lockfile(text: str) -> LockfileModel:
    """Every document in ``text``, merged into one model.

    Each document is read under its own header; the merged model reports the last
    one's, which is the project's. A key pinned by both documents is two rows, one per
    install.

    Raises ``LockfileParseError`` when the text is not a pnpm lockfile this module can
    read at all: not YAML in the subset, no document, a document that is not a mapping,
    no ``lockfileVersion`` or one with no grammar, a ``packages:`` that is not a mapping.
    A row that will not read is not one of those; it lands in ``unread``.
    """
    documents = [d for d in load_documents(text) if d is not None]  # a trailing `---`
    if not documents:
        raise LockfileParseError("no YAML document in the lockfile")
    models = [_read_document(document, index) for index, document in enumerate(documents)]
    if len(models) == 1:
        return models[0]
    merged = models[-1]  # pnpm writes the project's document last; the header is its
    for model in models[:-1]:
        merged.root_deps |= model.root_deps
        merged.packages = model.packages + merged.packages
        for name, edges in model.declared.items():
            merged.declared.setdefault(name, set()).update(edges)
        merged.unread = model.unread + merged.unread
    return merged


def _read_document(document: object, index: int) -> LockfileModel:
    if not isinstance(document, dict):
        raise LockfileParseError(f"document {index} is not a mapping")
    if "lockfileVersion" not in document:
        raise LockfileParseError(f"document {index} has no lockfileVersion")
    declared_version = document["lockfileVersion"]
    band = band_of(declared_version)
    packages = _section(document, "packages", index)
    snapshots = _section(document, "snapshots", index)

    grammar = declared_version
    rows = _rows(grammar, packages, snapshots)
    if band == "v9" and rows and all(record.status == UNKNOWN for _, _, record in rows):
        # The same keys, re-split: a row the 9.0 pass took from `snapshots:` stays a row,
        # so that nothing the document holds goes missing on the way to `unread`.
        legacy = [(key, entry, split_key(_LEGACY_GRAMMAR, key, entry))
                  for key, entry, _ in rows]
        if any(record.status != UNKNOWN for _, _, record in legacy):
            grammar, rows = _LEGACY_GRAMMAR, legacy

    importers = _importer_table(document, index)
    root_deps: set[str] = set()
    for importer in importers.values():
        if isinstance(importer, dict):
            root_deps |= _edges(importer, _IMPORTER_BLOCKS, grammar, packages, snapshots)

    installed: list[InstalledPackage] = []
    declared: dict[str, set[str]] = {ROOT: set(root_deps)}
    unread: list[str] = []
    for key, entry, record in rows:
        if record.status == UNKNOWN:
            unread.append(f"{key}: {record.reason}")
            continue
        if record.name is None:
            continue
        if record.version is not None:
            installed.append(InstalledPackage(name=record.name, version=record.version,
                                              path=key, origin=record.status))
        declared.setdefault(record.name, set()).update(
            _edges(entry, _PACKAGE_BLOCKS, grammar, packages, snapshots))
    # 9.0 edges live in snapshots, one entry per peer variant; all of them are the
    # package's edges. A snapshot whose base is also a row was split above already.
    if band == "v9" and grammar == declared_version:
        for key, entry in snapshots.items():
            record = split_key(grammar, key, entry, packages)
            if record.name is not None:
                declared.setdefault(record.name, set()).update(
                    _edges(entry, _PACKAGE_BLOCKS, grammar, packages, snapshots))

    # Only when nothing else already keeps this snapshot from reading clean: a
    # document with unread rows warns and cannot close an interval regardless, and a
    # missing pin is then likelier one of those rows than a second finding.
    if not unread:
        checked_snapshots = snapshots if band == "v9" and grammar == declared_version else {}
        unread += _pins_without_rows(importers, rows, checked_snapshots, installed)

    return LockfileModel(
        lockfile_version=str(declared_version).strip(),
        root_name="(unnamed)",
        root_deps=root_deps,
        packages=installed,
        declared=declared,
        unread=unread,
    )


def _importer_table(document: dict, index: int) -> dict:
    """The ``importers:`` mapping; absent means the document is its own importer.

    Present but not a mapping -- ``importers: []`` -- is refused rather than read as
    absent: the fallback would consult top-level blocks that are not there, report an
    empty project, and a malformed file would testify to a clean tree.
    """
    importers = document.get("importers")
    if importers is None:
        return {".": document}
    if not isinstance(importers, dict):
        raise LockfileParseError(
            f"document {index}: importers is a {type(importers).__name__}, not a mapping")
    for key, importer in importers.items():
        if importer is not None and not isinstance(importer, dict):
            raise LockfileParseError(
                f"document {index}: importer {key!r} is a "
                f"{type(importer).__name__}, not a mapping")
    return importers


def _pins_without_rows(importers: dict, rows: list[tuple[str, object, KeyRecord]],
                       snapshots: dict, installed: list[InstalledPackage]) -> list[str]:
    """Version pins the row sections do not hold: unread evidence, not a clean tree.

    YAML is prefix-valid where JSON is not, so a ``pnpm-lock.yaml`` truncated after any
    entry boundary still parses -- the importer records ``version: 5.6.1``, or a row
    still declares ``chalk: 5.6.1``, and the row that pinned it is gone. Reading that
    as "pins nothing" called the tree clean and silently ended exposure intervals,
    which is the one direction this tool must never be wrong in. Every version-shaped
    value -- in an importer block and in a row's dependency block alike, since the
    compromised package is usually transitive -- therefore requires a row of exactly
    that name and version; a name-only match would bless a hand-edited file whose pin
    and row disagree. A dep-path value (an alias, a git location) requires its key or
    a row answering to its name. Measured over 4,395 real files: 24 trip it (306
    pins), every one a vendored scanner fixture or a genuinely incomplete file -- one
    template repository resolves 68 devDependencies it holds no rows for. What stays
    invisible: a cut landing exactly between an importer's ``specifier:`` and
    ``version:`` lines leaves no version string to demand a row for.
    """
    held = {(p.name, p.version) for p in installed}
    row_names = {record.name for _, _, record in rows if record.name is not None}
    keys = {key for key, _, _ in rows} | set(snapshots)
    missing: dict[tuple[str, str], str] = {}

    def note(name: str, value: object) -> None:
        if isinstance(value, dict):
            value = value.get("version")
        if not isinstance(value, str) or not value:
            return
        # ``link:`` and ``workspace:`` targets legitimately have no row, and a
        # ``file:`` value's path is written relative to its importer, so its key
        # cannot be reconstructed from here.
        if value.startswith(("link:", "workspace:", "file:")):
            return
        # A pin that is a key of the document is backed, whatever it starts with --
        # decided before the digit test, because a dep-path can start with a digit
        # too (a numeric registry host, an alias to a digit-leading name).
        if value in keys or f"{name}@{value}" in keys:
            return
        if value[:1].isdigit():
            try:
                version = suffix_groups(value)[0].split("_", 1)[0]
            except Exception:
                # An unbalanced suffix is still a pin; a corrupted one proves less,
                # not more.
                missing.setdefault((name, value), value)
                return
            if (name, version) in held:
                return
            if "/" in version and name in row_names:
                return  # a digit-leading dep-path over bare keys; the name is backed
            missing.setdefault((name, version), value)
            return
        # An alias or a git location pins a row through a key, and the row it installs
        # carries a name of its own, so a row answering to the name also backs it -- a
        # mirror-registry file writes host-prefixed values over bare keys (measured).
        if name not in row_names:
            missing.setdefault((name, value), value)

    for importer in importers.values():
        if not isinstance(importer, dict):
            continue
        for block in _IMPORTER_BLOCKS:
            mapping = importer.get(block)
            if isinstance(mapping, dict):
                for name, value in mapping.items():
                    note(str(name), value)
    for entry in [entry for _, entry, _record in rows] + list(snapshots.values()):
        if isinstance(entry, dict):
            for block in _PACKAGE_BLOCKS:
                mapping = entry.get(block)
                if isinstance(mapping, dict):
                    for name, value in mapping.items():
                        note(str(name), value)
    return [f"{name}: the document resolves it to {value!r} and holds no row for "
            f"{name}@{version}" for (name, version), value in sorted(missing.items())]
def _section(document: dict, name: str, index: int) -> dict:
    """The ``packages:`` or ``snapshots:`` mapping; absent and empty are the same thing."""
    section = document.get(name)
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise LockfileParseError(
            f"document {index}: {name} is a {type(section).__name__}, not a mapping")
    return section


def _rows(grammar: object, packages: dict,
          snapshots: dict) -> list[tuple[str, object, KeyRecord]]:
    """``(key, entry, record)`` for every row of the document.

    5.x and 6.x rows are the ``packages:`` entries. 9.0 rows are the ``packages:``
    entries too, plus any snapshot that is not a variant of one of them: a snapshot
    that would not read (so the reason is reported), or one whose base has no
    ``packages:`` entry -- never observed, but a snapshot is a resolved install and
    dropping it would hide one.
    """
    rows = [(key, entry, split_key(grammar, key, entry, packages))
            for key, entry in packages.items()]
    if band_of(grammar) == "v9":
        for key, entry in snapshots.items():
            if key in packages:
                continue
            record = split_key(grammar, key, entry, packages)
            if record.status == UNKNOWN or suffix_groups(key)[0] not in packages:
                rows.append((key, entry, record))
    return rows


def _edges(entry: object, blocks: tuple[str, ...], grammar: object, packages: dict,
           snapshots: dict) -> set[str]:
    """Names an entry declares as dependencies, each resolved to the name it installs."""
    names: set[str] = set()
    if not isinstance(entry, dict):
        return names
    for block in blocks:
        mapping = entry.get(block)
        if not isinstance(mapping, dict):
            continue
        for declared_name, value in mapping.items():
            names.add(_target(str(declared_name), value, grammar, packages, snapshots))
    return names


def _target(declared_name: str, value: object, grammar: object, packages: dict,
            snapshots: dict) -> str:
    """The installed name an edge points at.

    An edge's value is a version (``5.6.1``, ``5.6.1(react@18.3.1)``, ``5.6.1_react@18``)
    or, for an alias or a git dependency, a dep-path. A dep-path is a key of the same
    document, so that is the test: a value that is a key resolves to the name that key
    installs, and anything else is an ordinary edge to the declared name. Inline
    specifiers (5.3-inlineSpecifiers, 6.x, 9.0 importers) wrap the value in a mapping.
    """
    if isinstance(value, dict):
        value = value.get("version")
    if not isinstance(value, str):
        return declared_name
    if value in packages:
        entry = packages[value]
    elif value in snapshots:
        entry = snapshots[value]
    else:
        return declared_name
    record = split_key(grammar, value, entry, packages)
    return record.name if record.name is not None else declared_name
