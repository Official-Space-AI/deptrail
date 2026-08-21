"""Unit tests for the lockfile parser across all three npm lockfile dialects.

Fixture trees are synthetic (real express/debug do not depend on chalk);
what matters is the structural shapes: nested duplicates, scoped names,
dev dependencies, v1 'requires' edges.
"""
import pathlib

import pytest

from deptrail.lockfile import (NOT_NPM, NPM, OTHER_REGISTRY, SOURCE, InstalledPackage,
                               LockfileModel, LockfileParseError, parse_lockfile)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(dialect: str) -> str:
    return (FIXTURES / dialect / "package-lock.json").read_text()


class TestPackagesFormat:
    def test_v3_basics(self):
        model = parse_lockfile(load("v3"))
        assert model.lockfile_version == "3"
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
        assert model.lockfile_version == "2"
        assert model.versions_of("chalk") == {"5.6.1"}
        assert model.chain_to("chalk") == ["express", "debug", "chalk"]


class TestV1Format:
    def test_v1_root_deps_heuristic(self):
        model = parse_lockfile(load("v1"))
        assert model.lockfile_version == "1"
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


class TestSchemaNormalization:
    """Regressions from review: every structural surprise must be LockfileParseError."""

    def test_non_numeric_lockfile_version(self):
        with pytest.raises(LockfileParseError):
            parse_lockfile('{"lockfileVersion": "three", "packages": {"": {}}}')

    def test_non_string_version_rejected(self):
        with pytest.raises(LockfileParseError):
            parse_lockfile(
                '{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": {"x": 1}}}}'
            )

    def test_malformed_root_entry_normalized(self):
        with pytest.raises(LockfileParseError):
            parse_lockfile('{"lockfileVersion": 3, "packages": {"": []}}')


def _model(*packages: InstalledPackage, declared=None, root_deps=None) -> LockfileModel:
    return LockfileModel(lockfile_version="0", root_name="t", root_deps=set(root_deps or ()),
                         packages=list(packages), declared=dict(declared or {}))


class TestOriginDecidesWhatAnAdvisoryCanMatch:
    """Real case behind this: ``vercel/next.js`` pins ``ci-info`` 2.0.0 from the registry
    and, separately, from a GitHub tarball whose package.json also says 2.0.0. An
    advisory for ``ci-info 2.0.0`` is about the registry artifact only."""

    def test_every_package_is_npm_unless_a_parser_says_otherwise(self):
        assert InstalledPackage("a", "1.0.0", "node_modules/a").origin == NPM
        for package in parse_lockfile(load("v3")).packages:
            assert package.origin == NPM

    def test_a_source_row_of_the_same_name_and_version_does_not_answer(self):
        model = _model(InstalledPackage("ci-info", "2.0.0", "ci-info@2.0.0"),
                       InstalledPackage("ci-info", "2.0.0", "ci-info@https://codeload/...",
                                        origin=SOURCE))
        assert model.versions_of("ci-info") == {"2.0.0"}
        assert len(model.packages) == 2, "the tarball stays in the inventory"

    @pytest.mark.parametrize("origin", [SOURCE, OTHER_REGISTRY, NOT_NPM])
    def test_a_name_installed_only_from_elsewhere_has_no_npm_versions(self, origin):
        model = _model(InstalledPackage("ci-info", "2.0.0", "k", origin=origin),
                       declared={"app": {"ci-info"}}, root_deps={"app"})
        assert model.versions_of("ci-info") == set()
        assert model.chain_to("ci-info") is None

    def test_the_same_name_from_two_origins_keeps_the_npm_versions_apart(self):
        model = _model(InstalledPackage("vue", "3.5.13", "vue@3.5.13"),
                       InstalledPackage("vue", "3.5.14", "vue@https://pkg.pr.new/...",
                                        origin=SOURCE),
                       InstalledPackage("vue", "3.4.0", "vue@3.4.0"))
        assert model.versions_of("vue") == {"3.5.13", "3.4.0"}


class TestUnreadRows:
    def test_a_parsed_npm_lockfile_reads_every_row(self):
        for dialect in ("v1", "v2", "v3"):
            assert parse_lockfile(load(dialect)).unread == []

    def test_unread_is_a_field_a_parser_can_fill(self):
        model = _model(InstalledPackage("a", "1.0.0", "a@1.0.0"))
        model.unread.append("weird@key: no name@version separator")
        assert model.unread == ["weird@key: no name@version separator"]
        assert model.versions_of("a") == {"1.0.0"}, "readable rows are still readable"


class TestTheDeclaredVersionIsText:
    """``int`` could not hold pnpm's ``5.3-inlineSpecifiers`` (issue #72); nothing reads
    the field as a number, so it holds what the file says."""

    @pytest.mark.parametrize("literal, text", [("3", "3"), ("2", "2"), ("3.0", "3")])
    def test_npm_integers_become_their_text(self, literal, text):
        model = parse_lockfile('{"lockfileVersion": %s, "packages": {"": {}}}' % literal)
        assert model.lockfile_version == text
        assert isinstance(model.lockfile_version, str)

    def test_an_npm_lockfile_without_the_field_is_read_as_2(self):
        assert parse_lockfile('{"packages": {"": {}}}').lockfile_version == "2"
