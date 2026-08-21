"""The normalized lockfile model, and the parser for npm lockfiles (lockfileVersion 1, 2, 3).

The forensic engine only needs two answers from a lockfile snapshot:
  1. which versions of a package were pinned at that point in history, and
  2. through which dependency chain the package entered the tree.
Everything else in the lockfile is deliberately ignored.

``LockfileModel`` is what every lockfile dialect is read into; the npm parser lives here
because it was the first, and the pnpm one (``pnpmlock``) builds the same model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

ROOT = "(root)"

# Where an installed package came from, which decides whether its (name, version) is an
# identity an npm advisory can be about. A git tarball whose package.json says 2.0.0 is
# not the registry's 2.0.0: reporting an advisory against it is a claim about a GitHub
# tarball, and merging the two rows did exactly that (``ci-info`` in ``vercel/next.js``).
# Dropping such rows instead is also wrong -- a pinned git tarball would vanish from the
# inventory -- so they stay, labelled, and ``versions_of`` leaves them out.
NPM = "npm"                        # the npmjs registry: match advisories on (name, version)
OTHER_REGISTRY = "other-registry"  # a registry that is not npmjs: JSR, or a named registry
SOURCE = "source"                  # a real name and version, but built from git or a tarball
NOT_NPM = "not-npm"                # not a package artifact at all: a runtime such as node
# The origins an advisory can be about. A registry that is not npmjs may be a proxy of it
# (Verdaccio and Nexus serve the npmjs tarball under the npmjs name), and a JSR name can
# never collide with an npmjs one, so a match on such a row is reported -- the report
# does not yet say which origin it came from (#83). A tarball built from git or a runtime
# is never the registry's artifact, whatever its version says.
REGISTRY_ORIGINS = frozenset({NPM, OTHER_REGISTRY})
_ORIGINS = frozenset({NPM, OTHER_REGISTRY, SOURCE, NOT_NPM})


class LockfileParseError(ValueError):
    """Raised when the input is not a lockfile format we understand."""


@dataclass(frozen=True)
class InstalledPackage:
    """One concrete package instance the lockfile pinned.

    ``path`` is where the instance sits: npm's tree location
    (``node_modules/a/node_modules/b``; ``""`` is the root project), or the lockfile key
    for a dialect without a tree, such as pnpm. A local directory link has no version
    and is not an instance; its dependencies still appear in ``LockfileModel.declared``.
    """

    name: str
    version: str
    path: str
    origin: str = NPM

    def __post_init__(self) -> None:
        # ``pnpmkeys.KeyRecord`` has an ``origin`` too, with a different vocabulary
        # (``registry``, ``git``, ...); a parser that copies it here would label every
        # row as something ``versions_of`` ignores, and every tree would read clean.
        if self.origin not in _ORIGINS:
            raise ValueError(f"origin {self.origin!r} is not one of {sorted(_ORIGINS)}")


@dataclass
class LockfileModel:
    """Normalized view of a lockfile snapshot, independent of lockfileVersion."""

    # The ``lockfileVersion`` the file declares, as text, because pnpm writes ``5.4``,
    # ``6.0`` and once ``5.3-inlineSpecifiers`` and nothing reads the field as a number.
    # The npm parser stores the integer npm writes, as text.
    lockfile_version: str
    root_name: str
    root_deps: set[str]
    packages: list[InstalledPackage]
    # declarer package name -> names it declares as dependencies (name-level graph)
    declared: dict[str, set[str]] = field(default_factory=dict)
    # Rows the parser found but could not read into a package, one message each. A
    # row that is not read is a version that may have been installed and is not shown
    # here, so ``history.py`` warns on a snapshot with anything in ``unread`` and does
    # not let it end an exposure interval. Raising instead would hide every row that
    # *was* readable; dropping the row would call the tree clean.
    unread: list[str] = field(default_factory=list)

    def instances_of(self, name: str) -> list[InstalledPackage]:
        """The instances of ``name`` an advisory can be about: see ``REGISTRY_ORIGINS``.

        The npm parser labels every row ``NPM``, including one resolved from a git URL;
        classifying those is issue #82. The pnpm parser labels rows by their key.
        """
        return [p for p in self.packages if p.name == name and p.origin in REGISTRY_ORIGINS]

    def versions_of(self, name: str) -> set[str]:
        """Versions of ``name`` an advisory can be about; ``SOURCE`` and ``NOT_NPM`` rows
        are still in ``packages`` for inventory and do not answer here."""
        return {p.version for p in self.instances_of(name)}

    def chain_to(self, name: str) -> list[str] | None:
        """Shortest name-level dependency chain from a direct dependency down to `name`.

        Chains are reconstructed on package *names*, not on concrete instances,
        because that is what an incident report needs to show a human
        ("express -> debug -> chalk"). Node's nearest-wins resolution of
        duplicated packages is intentionally not simulated here.

        Asked only about advisory targets, so ``None`` for a name that is installed
        solely from git or as a runtime: those rows are not what the chain is evidence
        for. Intermediate names need no instance at all -- a local directory link that
        only contributes edges still carries the chain through.
        """
        if not self.versions_of(name):
            return None
        # Reverse edges: dependency name -> the set of packages that declare it.
        declarers: dict[str, set[str]] = {}
        for parent, deps in self.declared.items():
            for dep in deps:
                declarers.setdefault(dep, set()).add(parent)

        # BFS upwards from the target until we hit a direct dependency of the root.
        queue: list[list[str]] = [[name]]
        seen = {name}
        while queue:
            chain = queue.pop(0)
            head = chain[0]
            if head in self.root_deps:
                return chain
            for parent in sorted(declarers.get(head, ())):
                if parent == ROOT:
                    return chain
                if parent not in seen:
                    seen.add(parent)
                    queue.append([parent, *chain])
        # Installed but not reachable through declared edges (e.g. orphan entry).
        return [name]


def parse_lockfile(text: str) -> LockfileModel:
    """Parse raw package-lock.json content of lockfileVersion 1, 2 or 3.

    Every structural surprise is normalized to LockfileParseError so callers can
    treat "this snapshot is unreadable" as one condition — a half-parsed lockfile
    must never crash a scan or pass as evidence.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise LockfileParseError(f"not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise LockfileParseError("lockfile root must be a JSON object")

    try:
        if isinstance(data.get("packages"), dict):
            return _parse_packages_format(data)  # lockfileVersion 2 and 3
        if isinstance(data.get("dependencies"), dict):
            return _parse_v1(data)
    except LockfileParseError:
        raise
    except Exception as e:
        raise LockfileParseError(
            f"malformed lockfile structure: {type(e).__name__}: {e}"
        ) from e
    raise LockfileParseError("neither 'packages' nor 'dependencies' present")


def _name_from_path(path: str) -> str:
    """'node_modules/a/node_modules/@s/b' -> '@s/b' (scoped names keep their scope)."""
    return path.rsplit("node_modules/", 1)[-1]


def _declared_names(entry: dict) -> set[str]:
    """Dependency names an entry declares; optional deps count, dev deps of the root count too.

    Dev dependencies matter for forensics: a compromised dev-only package still
    executes its install script on developer machines and CI runners.
    """
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        block = entry.get(key)
        if isinstance(block, dict):
            names.update(block)
    return names


def _parse_packages_format(data: dict) -> LockfileModel:
    # npm writes an integer; anything ``int()`` refuses is not an npm lockfile.
    version = str(int(data.get("lockfileVersion", 2)))
    packages_block: dict = data["packages"]
    root_entry = packages_block.get("", {})
    root_name = data.get("name") or root_entry.get("name") or "(unnamed)"

    installed: list[InstalledPackage] = []
    declared: dict[str, set[str]] = {ROOT: _declared_names(root_entry)}
    for path, entry in packages_block.items():
        if path == "" or not isinstance(entry, dict):
            continue
        if entry.get("link"):
            # Workspace links point outside the tree; out of scope for the MVP.
            continue
        name = entry.get("name") or _name_from_path(path)
        ver = entry.get("version")
        if ver is None:
            continue
        if not isinstance(ver, str):
            raise LockfileParseError(f"non-string version at {path!r}")
        installed.append(InstalledPackage(name=name, version=ver, path=path))
        declared.setdefault(name, set()).update(_declared_names(entry))

    return LockfileModel(
        lockfile_version=version,
        root_name=root_name,
        root_deps=set(declared[ROOT]),
        packages=installed,
        declared=declared,
    )


def _parse_v1(data: dict) -> LockfileModel:
    """lockfileVersion 1: a nested 'dependencies' tree with 'requires' edges.

    A v1 lockfile does not record which packages the root itself depends on,
    so we approximate: a top-level package that nobody 'requires' is treated
    as a direct dependency. This can over-count roots but never hides a chain.
    """
    installed: list[InstalledPackage] = []
    declared: dict[str, set[str]] = {}
    required_by_someone: set[str] = set()
    top_level = set(data["dependencies"].keys())

    def walk(block: dict, prefix: str) -> None:
        for name, entry in block.items():
            if not isinstance(entry, dict) or "version" not in entry:
                continue
            if not isinstance(entry["version"], str):
                raise LockfileParseError(f"non-string version for {name!r}")
            path = f"{prefix}node_modules/{name}"
            installed.append(InstalledPackage(name=name, version=entry["version"], path=path))
            requires = entry.get("requires")
            if isinstance(requires, dict):
                declared.setdefault(name, set()).update(requires)
                required_by_someone.update(requires)
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, f"{path}/")

    walk(data["dependencies"], "")
    root_deps = top_level - required_by_someone or top_level
    return LockfileModel(
        lockfile_version="1",
        root_name=data.get("name") or "(unnamed)",
        root_deps=root_deps,
        packages=installed,
        declared=declared,
    )
