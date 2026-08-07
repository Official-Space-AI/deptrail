"""Unit tests for the lockfile parser across all three npm lockfile dialects.

Fixture trees are synthetic (real express/debug do not depend on chalk);
what matters is the structural shapes: nested duplicates, scoped names,
dev dependencies, v1 'requires' edges.
"""
import pathlib

import pytest

from deptrail.lockfile import LockfileParseError, parse_lockfile

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(dialect: str) -> str:
    return (FIXTURES / dialect / "package-lock.json").read_text()


class TestPackagesFormat:
    def test_v3_basics(self):
        model = parse_lockfile(load("v3"))
        assert model.lockfile_version == 3
        assert model.root_name == "web-app"
        assert model.versions_of("express") == {"4.19.2"}

    def test_v3_duplicate_versions_are_both_visible(self):
        model = parse_lockfile(load("v3"))
        assert model.versions_of("chalk") == {"5.6.1", "4.1.2"}

    def test_v3_scoped_package_and_dev_dep_counted(self):
        model = parse_lockfile(load("v3"))
        assert model.versions_of("@scope/build-util") == {"1.2.3"}
        assert "@scope/build-util" in model.root_deps

    def test_v3_shortest_chain_wins(self):
        model = parse_lockfile(load("v3"))
        assert model.chain_to("chalk") == ["picolog", "chalk"]
        assert model.chain_to("debug") == ["express", "debug"]

    def test_v3_absent_package_has_no_chain(self):
        model = parse_lockfile(load("v3"))
        assert model.chain_to("left-pad") is None

    def test_v2_prefers_packages_block(self):
        model = parse_lockfile(load("v2"))
        assert model.lockfile_version == 2
        assert model.versions_of("chalk") == {"5.6.1"}
        assert model.chain_to("chalk") == ["express", "debug", "chalk"]


class TestV1Format:
    def test_v1_root_deps_heuristic(self):
        model = parse_lockfile(load("v1"))
        assert model.lockfile_version == 1
        assert model.root_deps == {"express", "chalk"}

    def test_v1_nested_package_path(self):
        model = parse_lockfile(load("v1"))
        assert model.versions_of("ansi-styles") == {"6.2.1"}
        paths = {p.path for p in model.packages if p.name == "ansi-styles"}
        assert paths == {"node_modules/chalk/node_modules/ansi-styles"}

    def test_v1_chain_through_requires(self):
        model = parse_lockfile(load("v1"))
        assert model.chain_to("ms") == ["express", "debug", "ms"]

    def test_v1_orphan_falls_back_to_bare_chain(self):
        model = parse_lockfile(load("v1"))
        assert model.chain_to("ansi-styles") == ["ansi-styles"]


class TestErrors:
    def test_not_json(self):
        with pytest.raises(LockfileParseError):
            parse_lockfile("definitely not json")

    def test_unknown_shape(self):
        with pytest.raises(LockfileParseError):
            parse_lockfile('{"name": "x", "version": "1.0.0"}')
